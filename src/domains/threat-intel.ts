/**
 * Threat Intelligence domain handler
 *
 * Provides tools for Proofpoint threat intelligence:
 * - Get threat details by threat ID
 * - Get campaign details by campaign ID
 * - Get threat families
 * - List indicators of compromise (IOCs)
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitText } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_threat_get_campaign",
      description:
        "Get details of a specific threat campaign by campaign ID. Returns campaign actors, malware families, techniques, and associated messages.",
      inputSchema: {
        type: "object" as const,
        properties: {
          campaign_id: {
            type: "string",
            description: "The campaign ID to look up",
          },
        },
        required: ["campaign_id"],
      },
    },
    {
      name: "proofpoint_threat_get_by_id",
      description:
        "Get detailed information about a specific threat by its threat ID. Returns threat type, classification, and associated indicators.",
      inputSchema: {
        type: "object" as const,
        properties: {
          threat_id: {
            type: "string",
            description: "The threat ID (SHA256 hash or Proofpoint threat ID)",
          },
        },
        required: ["threat_id"],
      },
    },
    {
      name: "proofpoint_threat_list_families",
      description:
        "List known threat families tracked by Proofpoint. Returns malware family names, descriptions, and associated campaigns.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to list families active since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
        },
      },
    },
    {
      name: "proofpoint_threat_get_iocs",
      description:
        "Get indicators of compromise (IOCs) for a specific campaign or time range. Returns URLs, IPs, domains, file hashes associated with threats.",
      inputSchema: {
        type: "object" as const,
        properties: {
          campaign_id: {
            type: "string",
            description: "Campaign ID to get IOCs for",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch IOCs since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threat_type: {
            type: "string",
            enum: ["url", "attachment", "messageText"],
            description: "Filter by threat type",
          },
        },
      },
    },
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_threat_get_campaign": {
      const campaignId = args.campaign_id as string;
      if (!campaignId) {
        return {
          content: [{ type: "text", text: "Error: campaign_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: threat.getCampaign", { campaignId });

      const result = await apiRequest<unknown>(
        `/v2/campaign/${encodeURIComponent(campaignId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_threat_get_by_id": {
      const threatId = args.threat_id as string;
      if (!threatId) {
        return {
          content: [{ type: "text", text: "Error: threat_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: threat.getById", { threatId });

      const result = await apiRequest<unknown>(
        `/v2/threat/summary/${encodeURIComponent(threatId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_threat_list_families": {
      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.sinceTime) params.sinceTime = args.sinceTime as string;
      if (args.interval) params.interval = args.interval as string;

      if (!args.sinceTime && !args.interval) {
        params.interval = "PT1H";
      }

      logger.info("API call: threat.listFamilies", params);

      const result = await apiRequest<unknown>("/v2/threat/families", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_threat_get_iocs": {
      // If no campaign_id and no time filter, ask for a campaign ID
      if (!args.campaign_id && !args.sinceTime && !args.interval) {
        const campaignId = await elicitText(
          "No campaign ID or time range specified. Enter a campaign ID to look up IOCs for, or leave blank to search the last hour.",
          "campaign_id",
          "Enter a Proofpoint campaign ID"
        );
        if (campaignId) {
          args = { ...args, campaign_id: campaignId };
        } else {
          args = { ...args, interval: "PT1H" };
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.sinceTime) params.sinceTime = args.sinceTime as string;
      if (args.interval) params.interval = args.interval as string;
      if (args.threat_type) params.threatType = args.threat_type as string;

      let path = "/v2/threat/iocs";
      if (args.campaign_id) {
        path = `/v2/campaign/${encodeURIComponent(args.campaign_id as string)}/iocs`;
      }

      logger.info("API call: threat.getIOCs", { path, params });

      const result = await apiRequest<unknown>(path, { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown threat intel tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const threatIntelHandler: DomainHandler = {
  getTools,
  handleCall,
};
