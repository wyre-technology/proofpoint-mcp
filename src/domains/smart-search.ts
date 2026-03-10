/**
 * Smart Search domain handler
 *
 * Provides tools for Proofpoint message tracing / Smart Search:
 * - Trace messages by various criteria (sender, recipient, subject, message ID)
 * - Get message details and delivery status
 *
 * API Reference: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/Smart_Search
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitText } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_smart_search_trace",
      description:
        "Trace messages through the Proofpoint mail flow. Search by sender, recipient, subject, or message ID to track delivery status and processing history.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender: {
            type: "string",
            description: "Sender email address to search for",
          },
          recipient: {
            type: "string",
            description: "Recipient email address to search for",
          },
          subject: {
            type: "string",
            description: "Subject line to search for (partial match)",
          },
          message_id: {
            type: "string",
            description: "Internet Message-ID header to search for",
          },
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
          },
          status: {
            type: "string",
            enum: ["delivered", "bounced", "quarantined", "rejected", "all"],
            description: "Filter by delivery status (default: all)",
          },
          page: {
            type: "number",
            description: "Page number (default: 1)",
          },
          per_page: {
            type: "number",
            description: "Results per page (default: 50)",
          },
        },
      },
    },
    {
      name: "proofpoint_smart_search_get_message",
      description:
        "Get detailed information about a specific message including headers, processing log, and delivery details.",
      inputSchema: {
        type: "object" as const,
        properties: {
          message_id: {
            type: "string",
            description: "The Proofpoint internal message ID",
          },
        },
        required: ["message_id"],
      },
    },
    {
      name: "proofpoint_smart_search_get_headers",
      description:
        "Get the full email headers for a specific message.",
      inputSchema: {
        type: "object" as const,
        properties: {
          message_id: {
            type: "string",
            description: "The Proofpoint internal message ID",
          },
        },
        required: ["message_id"],
      },
    },
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_smart_search_trace": {
      const hasFilters =
        args.sender || args.recipient || args.subject || args.message_id;

      // If no filters, elicit a search term
      if (!hasFilters) {
        const searchTerm = await elicitText(
          "No search criteria specified. Enter a sender or recipient email address to trace:",
          "email",
          "Sender or recipient email address"
        );
        if (searchTerm) {
          // Try to determine if it's a sender or recipient based on context
          args = { ...args, sender: searchTerm };
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {
        page: (args.page as number) || 1,
        per_page: (args.per_page as number) || 50,
      };

      if (args.sender) params.sender = args.sender as string;
      if (args.recipient) params.recipient = args.recipient as string;
      if (args.subject) params.subject = args.subject as string;
      if (args.message_id) params.messageID = args.message_id as string;
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;
      if (args.status && args.status !== "all") {
        params.status = args.status as string;
      }

      logger.info("API call: smartSearch.trace", params);

      const result = await apiRequest<unknown>("/v1/smart-search", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_smart_search_get_message": {
      const messageId = args.message_id as string;
      if (!messageId) {
        return {
          content: [{ type: "text", text: "Error: message_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: smartSearch.getMessage", { messageId });

      const result = await apiRequest<unknown>(
        `/v1/smart-search/messages/${encodeURIComponent(messageId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_smart_search_get_headers": {
      const messageId = args.message_id as string;
      if (!messageId) {
        return {
          content: [{ type: "text", text: "Error: message_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: smartSearch.getHeaders", { messageId });

      const result = await apiRequest<unknown>(
        `/v1/smart-search/messages/${encodeURIComponent(messageId)}/headers`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown smart search tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const smartSearchHandler: DomainHandler = {
  getTools,
  handleCall,
};
