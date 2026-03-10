/**
 * Forensics domain handler
 *
 * Provides tools for Proofpoint forensics and threat response:
 * - Get forensic data for a threat
 * - Get forensic data for a campaign
 * - Search and destroy (auto-pull) messages
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Forensics_API
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitConfirmation, elicitText } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_forensics_get_threat",
      description:
        "Get forensic evidence for a specific threat. Returns behavioral analysis, network activity, file modifications, and other forensic indicators.",
      inputSchema: {
        type: "object" as const,
        properties: {
          threat_id: {
            type: "string",
            description: "The threat ID to get forensics for",
          },
          includeCampaignForensics: {
            type: "boolean",
            description: "Include forensics for the entire campaign (default: false)",
          },
        },
        required: ["threat_id"],
      },
    },
    {
      name: "proofpoint_forensics_get_campaign",
      description:
        "Get forensic evidence for all threats in a campaign. Returns aggregated behavioral analysis across all associated threats.",
      inputSchema: {
        type: "object" as const,
        properties: {
          campaign_id: {
            type: "string",
            description: "The campaign ID to get forensics for",
          },
        },
        required: ["campaign_id"],
      },
    },
    {
      name: "proofpoint_forensics_search_messages",
      description:
        "Search for messages across mailboxes for threat response. Used for search & destroy / auto-pull operations to find and remediate delivered threats.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender: {
            type: "string",
            description: "Sender email address to search for",
          },
          subject: {
            type: "string",
            description: "Subject line to search for (partial match)",
          },
          message_id: {
            type: "string",
            description: "Internet message ID to search for",
          },
          threat_id: {
            type: "string",
            description: "Threat ID associated with messages to find",
          },
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
          },
        },
      },
    },
    {
      name: "proofpoint_forensics_pull_messages",
      description:
        "Auto-pull (search & destroy) messages from mailboxes. This is a destructive operation that removes delivered messages from user mailboxes.",
      inputSchema: {
        type: "object" as const,
        properties: {
          message_ids: {
            type: "array",
            items: { type: "string" },
            description: "Array of message IDs to pull from mailboxes",
          },
          reason: {
            type: "string",
            description: "Reason for pulling messages (for audit trail)",
          },
        },
        required: ["message_ids"],
      },
    },
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_forensics_get_threat": {
      const threatId = args.threat_id as string;
      if (!threatId) {
        return {
          content: [{ type: "text", text: "Error: threat_id is required" }],
          isError: true,
        };
      }

      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.includeCampaignForensics) {
        params.includeCampaignForensics = true;
      }

      logger.info("API call: forensics.getThreat", { threatId });

      const result = await apiRequest<unknown>(
        `/v2/forensics/threat/${encodeURIComponent(threatId)}`,
        { params }
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_forensics_get_campaign": {
      const campaignId = args.campaign_id as string;
      if (!campaignId) {
        return {
          content: [{ type: "text", text: "Error: campaign_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: forensics.getCampaign", { campaignId });

      const result = await apiRequest<unknown>(
        `/v2/forensics/campaign/${encodeURIComponent(campaignId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_forensics_search_messages": {
      // If no search criteria, elicit a sender or subject
      const hasFilters =
        args.sender || args.subject || args.message_id || args.threat_id;

      if (!hasFilters) {
        const sender = await elicitText(
          "No search criteria specified. Enter a sender email address to search for:",
          "sender",
          "Sender email address"
        );
        if (sender) {
          args = { ...args, sender };
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.sender) params.sender = args.sender as string;
      if (args.subject) params.subject = args.subject as string;
      if (args.message_id) params.messageID = args.message_id as string;
      if (args.threat_id) params.threatID = args.threat_id as string;
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;

      logger.info("API call: forensics.searchMessages", params);

      const result = await apiRequest<unknown>("/v1/trap/search", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_forensics_pull_messages": {
      const messageIds = args.message_ids as string[];
      if (!messageIds || messageIds.length === 0) {
        return {
          content: [{ type: "text", text: "Error: message_ids array is required and must not be empty" }],
          isError: true,
        };
      }

      // Confirm destructive action
      const confirmed = await elicitConfirmation(
        `Are you sure you want to pull ${messageIds.length} message(s) from user mailboxes? This will remove the messages and cannot be easily undone.`
      );
      if (confirmed === false) {
        return {
          content: [{ type: "text", text: "Auto-pull cancelled by user." }],
        };
      }

      logger.info("API call: forensics.pullMessages", {
        count: messageIds.length,
        reason: args.reason,
      });

      const result = await apiRequest<unknown>("/v1/trap/pull", {
        method: "POST",
        body: {
          messageIds,
          reason: (args.reason as string) || "Threat remediation via MCP",
        },
      });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                success: true,
                message: `Initiated auto-pull for ${messageIds.length} message(s)`,
                result,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown forensics tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const forensicsHandler: DomainHandler = {
  getTools,
  handleCall,
};
