/**
 * URL Defense domain handler
 *
 * Provides tools for Proofpoint URL Defense:
 * - Decode Proofpoint-rewritten URLs back to original
 * - Analyze URLs for threats
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/URL_Decoder_API
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_url_decode",
      description:
        "Decode one or more Proofpoint URL Defense rewritten URLs back to the original URLs. Proofpoint rewrites URLs in emails for click-time protection; this tool reverses that encoding.",
      inputSchema: {
        type: "object" as const,
        properties: {
          urls: {
            type: "array",
            items: { type: "string" },
            description:
              "Array of Proofpoint-encoded URLs to decode (e.g., https://urldefense.proofpoint.com/v2/url?...)",
          },
        },
        required: ["urls"],
      },
    },
    {
      name: "proofpoint_url_analyze",
      description:
        "Analyze a URL for threats. Returns threat classification, risk score, and associated campaigns.",
      inputSchema: {
        type: "object" as const,
        properties: {
          url: {
            type: "string",
            description: "URL to analyze for threats",
          },
        },
        required: ["url"],
      },
    },
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_url_decode": {
      const urls = args.urls as string[];
      if (!urls || urls.length === 0) {
        return {
          content: [{ type: "text", text: "Error: urls array is required and must not be empty" }],
          isError: true,
        };
      }

      logger.info("API call: urlDefense.decode", { count: urls.length });

      const result = await apiRequest<unknown>("/v2/url/decode", {
        method: "POST",
        body: { urls },
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_url_analyze": {
      const url = args.url as string;
      if (!url) {
        return {
          content: [{ type: "text", text: "Error: url is required" }],
          isError: true,
        };
      }

      logger.info("API call: urlDefense.analyze", { url });

      const result = await apiRequest<unknown>("/v2/url/analyze", {
        method: "POST",
        body: { url },
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown URL defense tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const urlDefenseHandler: DomainHandler = {
  getTools,
  handleCall,
};
