#!/usr/bin/env node
/**
 * Proofpoint MCP Server with Decision Tree Architecture
 *
 * This MCP server uses a hierarchical tool loading approach:
 * 1. Initially exposes only a navigation tool
 * 2. After user selects a domain, exposes domain-specific tools
 * 3. Lazy-loads domain handlers on first access
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
import { getCredentials } from "./utils/client.js";
import { logger } from "./utils/logger.js";
import { setServerRef } from "./utils/server-ref.js";
import {
  TOOL_CATEGORIES,
  buildToolToCategoryMap,
  routeIntent,
} from "./utils/categories.js";

// Lazy-loading mode flag
const LAZY_LOADING = process.env.LAZY_LOADING === "true";

// Server navigation state
let currentDomain: DomainName | null = null;

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
 * Navigation tool - shown when at root (no domain selected)
 */
const navigateTool: Tool = {
  name: "proofpoint_navigate",
  description:
    "Navigate to a Proofpoint domain to access its tools. Available domains: tap (Targeted Attack Protection - SIEM threats/clicks/messages), quarantine (manage email quarantine), threat_intel (IOCs, campaigns, threat families), dlp (data loss prevention & encryption), people (user risk scores & VAP reports), forensics (threat response & search-and-destroy), smart_search (message tracing), policy (email security policies), url_defense (URL decoding & analysis), events (spam/phish/malware detections), reports (org-level security reports).",
  inputSchema: {
    type: "object",
    properties: {
      domain: {
        type: "string",
        enum: getAvailableDomains(),
        description:
          "The domain to navigate to",
      },
    },
    required: ["domain"],
  },
};

/**
 * Back navigation tool - shown when inside a domain
 */
const backTool: Tool = {
  name: "proofpoint_back",
  description: "Navigate back to the main menu to select a different domain",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

/**
 * Status tool - always available
 */
const statusTool: Tool = {
  name: "proofpoint_status",
  description:
    "Show current navigation state and available domains. Also verifies API credentials are configured.",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

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

/**
 * Get tools based on current navigation state
 */
async function getToolsForState(): Promise<Tool[]> {
  const tools: Tool[] = [statusTool];

  if (currentDomain === null) {
    tools.unshift(navigateTool);
  } else {
    tools.unshift(backTool);
    const handler = await getDomainHandler(currentDomain);
    const domainTools = handler.getTools();
    tools.push(...domainTools);
  }

  return tools;
}

// Handle ListTools requests
server.setRequestHandler(ListToolsRequestSchema, async () => {
  if (LAZY_LOADING) {
    return { tools: metaTools };
  }
  const tools = await getToolsForState();
  return { tools };
});

// Handle CallTool requests
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  logger.info("Tool call received", { tool: name, arguments: args });

  try {
    // Navigate to a domain
    if (name === "proofpoint_navigate") {
      const domain = (args as { domain: string }).domain;

      if (!isDomainName(domain)) {
        return {
          content: [
            {
              type: "text",
              text: `Invalid domain: '${domain}'. Available domains: ${getAvailableDomains().join(", ")}`,
            },
          ],
          isError: true,
        };
      }

      // Validate credentials before allowing navigation
      const creds = getCredentials();
      if (!creds) {
        return {
          content: [
            {
              type: "text",
              text: "Error: No API credentials configured. Please set the PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET environment variables.",
            },
          ],
          isError: true,
        };
      }

      currentDomain = domain;
      const handler = await getDomainHandler(domain);
      const domainTools = handler.getTools();

      logger.info("Navigated to domain", { domain, toolCount: domainTools.length });

      return {
        content: [
          {
            type: "text",
            text: `Navigated to ${domain} domain.\n\nAvailable tools:\n${domainTools
              .map((t) => `- ${t.name}: ${t.description}`)
              .join("\n")}\n\nUse proofpoint_back to return to the main menu.`,
          },
        ],
      };
    }

    // Navigate back to root
    if (name === "proofpoint_back") {
      const previousDomain = currentDomain;
      currentDomain = null;

      return {
        content: [
          {
            type: "text",
            text: `Navigated back from ${previousDomain || "root"} to the main menu.\n\nAvailable domains: ${getAvailableDomains().join(", ")}\n\nUse proofpoint_navigate to select a domain.`,
          },
        ],
      };
    }

    // Status check
    if (name === "proofpoint_status") {
      const creds = getCredentials();
      const credStatus = creds
        ? "Configured"
        : "NOT CONFIGURED - Please set PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET environment variables";

      return {
        content: [
          {
            type: "text",
            text: `Proofpoint MCP Server Status\n\nCurrent domain: ${currentDomain || "(none - at main menu)"}\nCredentials: ${credStatus}\nAvailable domains: ${getAvailableDomains().join(", ")}`,
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

    // Domain-specific tool calls (decision-tree mode)
    if (currentDomain !== null) {
      const handler = await getDomainHandler(currentDomain);
      const domainTools = handler.getTools();
      const toolExists = domainTools.some((t) => t.name === name);

      if (toolExists) {
        const result = await handler.handleCall(name, args as Record<string, unknown>);
        logger.debug("Tool call completed", {
          tool: name,
          responseSize: JSON.stringify(result).length,
        });
        return result;
      }
    }

    // Tool not found
    return {
      content: [
        {
          type: "text",
          text: currentDomain
            ? `Unknown tool: '${name}'. You are in the '${currentDomain}' domain. Use proofpoint_back to return to the main menu.`
            : `Unknown tool: '${name}'. Use proofpoint_navigate to select a domain first.`,
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
  logger.info(`Proofpoint MCP server running on stdio (${LAZY_LOADING ? "lazy-loading" : "decision-tree"} mode)`);
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

        // Set env vars so getCredentials() picks them up
        process.env.PROOFPOINT_SERVICE_PRINCIPAL = principal;
        process.env.PROOFPOINT_SERVICE_SECRET = secret;
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
    toolMode: LAZY_LOADING ? "lazy-loading" : "decision-tree",
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
