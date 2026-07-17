// MCP Resource Handlers for the Proofpoint MCP Server
// Exposes the MCP Apps (SEP-1865) threat-card UI via ListResources and
// ReadResource handlers. The card HTML is embedded at build time
// (src/generated/threat-card-html.ts) so it serves identically from stdio
// and the Node HTTP transport without any filesystem access.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  THREAT_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
  applyBrandInjection,
  resolveBrandFromEnv,
} from "./card.builder.js";
import { THREAT_CARD_HTML } from "./generated/threat-card-html.js";

export interface McpResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpResourceContent {
  uri: string;
  mimeType: string;
  text: string;
}

export function listResources(): McpResource[] {
  return [
    {
      uri: THREAT_CARD_RESOURCE_URI,
      name: "Proofpoint Threat Card",
      description: "Interactive MCP Apps card rendering a Proofpoint TAP threat summary",
      mimeType: MCP_APP_RESOURCE_MIME,
    },
  ];
}

export function readResource(uri: string): McpResourceContent {
  if (uri === THREAT_CARD_RESOURCE_URI) {
    return {
      uri,
      mimeType: MCP_APP_RESOURCE_MIME,
      // Neutral by default; MCP_BRAND_* env vars inject a per-operator brand
      // at serve time (no rebuild needed). Empty brand = HTML served as-is.
      text: applyBrandInjection(THREAT_CARD_HTML, resolveBrandFromEnv()),
    };
  }
  throw new Error(`Unknown resource: ${uri}`);
}

export function registerResourceHandlers(server: Server): void {
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: listResources(),
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => ({
    contents: [readResource(request.params.uri)],
  }));
}
