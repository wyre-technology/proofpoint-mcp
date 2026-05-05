#!/usr/bin/env node
/**
 * Proofpoint MCP Server
 *
 * This MCP server provides tools for interacting with the Proofpoint Email Protection API.
 * All tools are listed upfront so they work with every MCP client, including
 * remote connectors (claude.ai, mcp-remote) that do not support dynamic
 * tool-list changes. A helper `proofpoint_navigate` tool provides domain
 * discovery and guidance.
 *
 * Supports both stdio and HTTP transports:
 * - stdio (default): For local Claude Desktop / CLI usage
 * - http: For hosted deployment with optional gateway auth
 *
 * Auth modes:
 * - env (default): Credentials from PROOFPOINT_SERVICE_PRINCIPAL and
 *   PROOFPOINT_SERVICE_SECRET environment variables
 * - gateway: Credentials injected from request headers by the MCP gateway
 *   - Header: X-Proofpoint-Service-Principal
 *   - Header: X-Proofpoint-Service-Secret
 *
 * Domains:
 * - tap: Targeted Attack Protection (SIEM API) - threats, clicks, messages
 * - quarantine: Quarantine management - list, release, delete, search
 * - threat_intel: Threat intelligence - IOCs, threat families, campaigns
 * - dlp: Email DLP and encryption
 * - people: User risk scoring and Very Attacked People (VAP) reports
 * - forensics: Forensics and threat response - auto-pull, search & destroy
 * - smart_search: Message tracing / Smart Search
 * - policy: Policy management
 * - url_defense: URL decoding and analysis
 * - events: Spam/phishing/malware detection events
 * - reports: Organization-level security reports
 */

import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { getDomainHandler, getAvailableDomains } from "./domains/index.js";
import { isDomainName, type DomainName } from "./utils/types.js";
import { getCredentials, runWithCredentials } from "./utils/client.js";
import { logger } from "./utils/logger.js";
import { setServerRef } from "./utils/server-ref.js";
import {
  TOOL_CATEGORIES,
  buildToolToCategoryMap,
  routeIntent,
} from "./utils/categories.js";

// Lazy-loading mode flag
const LAZY_LOADING = process.env.LAZY_LOADING === "true";

// Create the MCP server
const server = new Server(
  {
    name: "mcp-server-proofpoint",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

setServerRef(server);

/**
 * Available domains for navigation
 */
type Domain = DomainName;

/**
 * Domain metadata for navigation
 */
const domainDescriptions: Record<Domain, string> = {
  tap: "Targeted Attack Protection (TAP) - SIEM API for threats, clicks, messages, and attack intelligence",
  quarantine: "Quarantine management - list, release, delete, and search quarantined email messages",
  threat_intel: "Threat intelligence - IOCs, threat families, campaigns, and security indicators",
  dlp: "Data Loss Prevention & email encryption - manage sensitive data protection policies",
  people: "User risk scoring and Very Attacked People (VAP) reports - identify high-risk users",
  forensics: "Forensics and threat response - auto-pull, search & destroy malicious content",
  smart_search: "Message tracing / Smart Search - track email delivery and routing",
  policy: "Policy management - configure email security rules and enforcement",
  url_defense: "URL Defense - URL decoding, analysis, and malicious link protection",
  events: "Security events - spam, phishing, and malware detection alerts",
  reports: "Organization-level security reports - threat summaries and analytics",
};

/**
 * Navigation / discovery tool - helps the LLM find the right tools
 *
 * This is a stateless helper that describes available tools for a domain.
 * All domain tools are always listed in tools/list regardless of navigation
 * state, because many MCP clients (claude.ai connectors, mcp-remote) only
 * fetch the tool list once and do not support notifications/tools/list_changed.
 */
const navigateTool: Tool = {
  name: "proofpoint_navigate",
  description:
    "Discover available Proofpoint tools by domain. Returns tool names and descriptions for the selected domain. All tools are callable at any time — this is a help/discovery aid, not a prerequisite.",
  inputSchema: {
    type: "object",
    properties: {
      domain: {
        type: "string",
        enum: getAvailableDomains(),
        description: `The domain to explore:
- tap: ${domainDescriptions.tap}
- quarantine: ${domainDescriptions.quarantine}
- threat_intel: ${domainDescriptions.threat_intel}
- dlp: ${domainDescriptions.dlp}
- people: ${domainDescriptions.people}
- forensics: ${domainDescriptions.forensics}
- smart_search: ${domainDescriptions.smart_search}
- policy: ${domainDescriptions.policy}
- url_defense: ${domainDescriptions.url_defense}
- events: ${domainDescriptions.events}
- reports: ${domainDescriptions.reports}`,
      },
    },
    required: ["domain"],
  },
};

/**
 * Status tool - shows credentials status and available domains
 */
const statusTool: Tool = {
  name: "proofpoint_status",
  description: "Show credentials status and available domains",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

/**
 * Map from domain name to its tool definitions (loaded lazily)
 */
const domainToolMap = new Map<DomainName, Tool[]>();

/**
 * All domain tools, collected once at startup
 */
let allDomainTools: Tool[] | null = null;

/**
 * Load all domain tools (lazy-loaded on first access)
 */
async function getAllDomainTools(): Promise<Tool[]> {
  if (allDomainTools !== null) {
    return allDomainTools;
  }

  const domains = getAvailableDomains();
  const tools: Tool[] = [];

  for (const domain of domains) {
    if (!domainToolMap.has(domain)) {
      const handler = await getDomainHandler(domain);
      const domainTools = handler.getTools();
      domainToolMap.set(domain, domainTools);
    }
    tools.push(...domainToolMap.get(domain)!);
  }

  allDomainTools = tools;
  return tools;
}

// ──────────────────────────────────────────────────────────
// Lazy-loading meta-tools (active when LAZY_LOADING=true)
// ──────────────────────────────────────────────────────────

const toolToCategoryMap = buildToolToCategoryMap();

const metaToolListCategories: Tool = {
  name: "proofpoint_list_categories",
  description:
    "List all Proofpoint tool categories with descriptions and tool counts. Use this to discover what capabilities are available.",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

const metaToolListCategoryTools: Tool = {
  name: "proofpoint_list_category_tools",
  description:
    "List the full tool schemas for a specific category. Call this to see detailed input schemas before executing a tool.",
  inputSchema: {
    type: "object",
    properties: {
      category: {
        type: "string",
        enum: Object.keys(TOOL_CATEGORIES),
        description: "The category to list tools for",
      },
    },
    required: ["category"],
  },
};

const metaToolExecute: Tool = {
  name: "proofpoint_execute_tool",
  description:
    "Execute any Proofpoint tool by name. Use proofpoint_list_category_tools first to discover available tools and their schemas.",
  inputSchema: {
    type: "object",
    properties: {
      toolName: {
        type: "string",
        description: "The full tool name to execute (e.g. proofpoint_tap_get_all_threats)",
      },
      arguments: {
        type: "object",
        description: "The arguments to pass to the tool",
        additionalProperties: true,
      },
    },
    required: ["toolName"],
  },
};

const metaToolRouter: Tool = {
  name: "proofpoint_router",
  description:
    "Describe what you want to do in plain English and get suggestions for which category and tools to use.",
  inputSchema: {
    type: "object",
    properties: {
      intent: {
        type: "string",
        description:
          "A natural language description of what you want to accomplish (e.g. 'find phishing threats from last 24 hours')",
      },
    },
    required: ["intent"],
  },
};

const metaTools: Tool[] = [
  metaToolListCategories,
  metaToolListCategoryTools,
  metaToolExecute,
  metaToolRouter,
];

// Handle ListTools requests - always returns ALL tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  if (LAZY_LOADING) {
    return { tools: metaTools };
  }
  const domainTools = await getAllDomainTools();
  return { tools: [navigateTool, statusTool, ...domainTools] };
});

// Handle CallTool requests
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  logger.info("Tool call received", { tool: name, arguments: args });

  try {
    // Handle navigation / discovery helper
    if (name === "proofpoint_navigate") {
      const { domain } = args as { domain: Domain };

      if (!isDomainName(domain)) {
        return {
          content: [
            {
              type: "text",
              text: `Invalid domain: ${domain}. Available domains: ${getAvailableDomains().join(", ")}`,
            },
          ],
          isError: true,
        };
      }

      const handler = await getDomainHandler(domain);
      const tools = handler.getTools();

      const toolSummary = tools
        .map((t) => `- ${t.name}: ${t.description}`)
        .join("\n");

      return {
        content: [
          {
            type: "text",
            text: `${domainDescriptions[domain]}\n\nAvailable tools:\n${toolSummary}\n\nYou can call any of these tools directly.`,
          },
        ],
      };
    }

    if (name === "proofpoint_status") {
      const creds = getCredentials();
      const credStatus = creds
        ? "Configured"
        : "NOT CONFIGURED - Please set PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET environment variables";

      return {
        content: [
          {
            type: "text",
            text: `Proofpoint MCP Server Status\n\nCredentials: ${credStatus}\nAvailable domains: ${getAvailableDomains().join(", ")}\n\nAll tools are available at all times. Use proofpoint_navigate to discover tools by domain.`,
          },
        ],
      };
    }

    // ── Lazy-loading meta-tool handlers ──

    if (name === "proofpoint_list_categories") {
      const categories = Object.entries(TOOL_CATEGORIES).map(
        ([catName, cat]) => ({
          name: catName,
          description: cat.description,
          toolCount: cat.tools.length,
        })
      );
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ categories }, null, 2),
          },
        ],
      };
    }

    if (name === "proofpoint_list_category_tools") {
      const { category } = args as { category: string };
      const cat = TOOL_CATEGORIES[category];
      if (!cat) {
        return {
          content: [
            {
              type: "text",
              text: `Unknown category: '${category}'. Available: ${Object.keys(TOOL_CATEGORIES).join(", ")}`,
            },
          ],
          isError: true,
        };
      }
      const handler = await getDomainHandler(cat.domain);
      const domainTools = handler.getTools();
      // Only return tools that belong to this category
      const filtered = domainTools.filter((t) => cat.tools.includes(t.name));
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ category, tools: filtered }, null, 2),
          },
        ],
      };
    }

    if (name === "proofpoint_execute_tool") {
      const { toolName, arguments: toolArgs } = args as {
        toolName: string;
        arguments?: Record<string, unknown>;
      };
      const categoryName = toolToCategoryMap.get(toolName);
      if (!categoryName) {
        return {
          content: [
            {
              type: "text",
              text: `Unknown tool: '${toolName}'. Use proofpoint_list_categories and proofpoint_list_category_tools to discover available tools.`,
            },
          ],
          isError: true,
        };
      }
      const cat = TOOL_CATEGORIES[categoryName];
      const handler = await getDomainHandler(cat.domain);
      return handler.handleCall(toolName, toolArgs ?? {});
    }

    if (name === "proofpoint_router") {
      const { intent } = args as { intent: string };
      const matchedCategories = routeIntent(intent);

      if (matchedCategories.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: `No matching categories found for: "${intent}". Use proofpoint_list_categories to see all available categories.`,
            },
          ],
        };
      }

      const suggestions = matchedCategories.slice(0, 3).map((catName) => {
        const cat = TOOL_CATEGORIES[catName];
        return {
          category: catName,
          description: cat.description,
          tools: cat.tools,
        };
      });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                intent,
                suggestions,
                hint: "Use proofpoint_list_category_tools to see full schemas, then proofpoint_execute_tool to run a tool.",
              },
              null,
              2
            ),
          },
        ],
      };
    }

    // Route to appropriate domain handler based on tool prefix
    const toolArgs = (args ?? {}) as Record<string, unknown>;

    if (name.startsWith("proofpoint_tap_")) {
      const handler = await getDomainHandler("tap");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_quarantine_")) {
      const handler = await getDomainHandler("quarantine");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_threat_intel_")) {
      const handler = await getDomainHandler("threat_intel");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_dlp_")) {
      const handler = await getDomainHandler("dlp");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_people_")) {
      const handler = await getDomainHandler("people");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_forensics_")) {
      const handler = await getDomainHandler("forensics");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_smart_search_")) {
      const handler = await getDomainHandler("smart_search");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_policy_")) {
      const handler = await getDomainHandler("policy");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_url_defense_")) {
      const handler = await getDomainHandler("url_defense");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_events_")) {
      const handler = await getDomainHandler("events");
      return await handler.handleCall(name, toolArgs);
    }
    if (name.startsWith("proofpoint_reports_")) {
      const handler = await getDomainHandler("reports");
      return await handler.handleCall(name, toolArgs);
    }

    // Unknown tool
    return {
      content: [
        {
          type: "text",
          text: `Unknown tool: ${name}. Use proofpoint_navigate to discover available tools by domain.`,
        },
      ],
      isError: true,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stack = error instanceof Error ? error.stack : undefined;
    logger.error("Tool call failed", { tool: name, error: message, stack });
    return {
      content: [{ type: "text", text: `Error: ${message}` }],
      isError: true,
    };
  }
});

/**
 * Start the server with stdio transport (default)
 */
async function startStdioTransport(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info(`Proofpoint MCP server running on stdio (${LAZY_LOADING ? "lazy-loading" : "flattened"} mode)`);
}

/**
 * Start the server with HTTP Streamable transport.
 * In gateway mode (AUTH_MODE=gateway), credentials are extracted
 * from the X-Proofpoint-Service-Principal and X-Proofpoint-Service-Secret
 * request headers.
 */
async function startHttpTransport(): Promise<void> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = process.env.MCP_HTTP_HOST || "0.0.0.0";
  const isGatewayMode = process.env.AUTH_MODE === "gateway";

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
  });

  const httpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    // Health check - no auth required
    if (url.pathname === "/health") {
      const creds = getCredentials();
      const statusCode = creds ? 200 : 503;

      res.writeHead(statusCode, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: creds ? "ok" : "degraded",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          timestamp: new Date().toISOString(),
          credentials: {
            configured: !!creds,
          },
          logLevel: process.env.LOG_LEVEL || "info",
          version: "1.0.0",
        })
      );
      return;
    }

    // MCP endpoint
    if (url.pathname === "/mcp") {
      // Gateway mode: extract credentials from headers
      if (isGatewayMode) {
        const principal = req.headers["x-proofpoint-service-principal"] as string | undefined;
        const secret = req.headers["x-proofpoint-service-secret"] as string | undefined;

        if (!principal || !secret) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing credentials",
              message:
                "Gateway mode requires X-Proofpoint-Service-Principal and X-Proofpoint-Service-Secret headers",
              required: ["X-Proofpoint-Service-Principal", "X-Proofpoint-Service-Secret"],
            })
          );
          return;
        }

        // Pass credentials via AsyncLocalStorage so concurrent requests
        // cannot leak credentials across tenants.
        runWithCredentials(
          {
            servicePrincipal: principal,
            serviceSecret: secret,
            baseUrl: process.env.PROOFPOINT_BASE_URL || "https://tap-api-v2.proofpoint.com",
          },
          () => transport.handleRequest(req, res),
        );
        return;
      }

      transport.handleRequest(req, res);
      return;
    }

    // 404 for everything else
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  await server.connect(transport);

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      logger.info(`Proofpoint MCP server listening on http://${host}:${port}/mcp`);
      logger.info(`Health check available at http://${host}:${port}/health`);
      logger.info(
        `Authentication mode: ${isGatewayMode ? "gateway (X-Proofpoint-Service-Principal/Secret headers)" : "env (PROOFPOINT_SERVICE_PRINCIPAL/SECRET environment variables)"}`
      );
      resolve();
    });
  });

  // Graceful shutdown
  const shutdown = async () => {
    logger.info("Shutting down Proofpoint MCP server...");
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
    await server.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

/**
 * Main entry point - select transport based on MCP_TRANSPORT env var
 */
async function main() {
  const transportType = process.env.MCP_TRANSPORT || "stdio";
  logger.info("Starting Proofpoint MCP server", {
    transport: transportType,
    toolMode: LAZY_LOADING ? "lazy-loading" : "flattened",
    logLevel: process.env.LOG_LEVEL || "info",
    nodeVersion: process.version,
  });

  if (transportType === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

main().catch((error) => {
  logger.error("Fatal startup error", {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  process.exit(1);
});
