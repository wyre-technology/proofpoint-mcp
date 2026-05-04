/**
 * Quarantine domain handler
 *
 * Provides tools for managing the Proofpoint email quarantine:
 * - List quarantined messages
 * - Search quarantine by various criteria
 * - Release quarantined messages
 * - Delete quarantined messages
 *
 * API Reference: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/Quarantine
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitText, elicitConfirmation } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_quarantine_list",
      description:
        "List quarantined messages. Returns messages held in quarantine with sender, recipient, subject, and reason.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sender: {
            type: "string",
            description: "Filter by sender email address",
          },
          recipient: {
            type: "string",
            description: "Filter by recipient email address",
          },
          subject: {
            type: "string",
            description: "Filter by subject (partial match)",
          },
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
          },
          folder: {
            type: "string",
            enum: ["SPAM", "VIRUS", "POLICY", "BULK", "PHISH", "ADMIN", "IMPOSTOR"],
            description: "Filter by quarantine folder/reason",
          },
          page: {
            type: "number",
            description: "Page number for pagination (default: 1)",
          },
          per_page: {
            type: "number",
            description: "Number of results per page (default: 50)",
          },
        },
      },
    },
    {
      name: "proofpoint_quarantine_search",
      description:
        "Search quarantine by keyword across sender, recipient, and subject fields.",
      inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "Search keyword to find in sender, recipient, or subject",
          },
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
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
        required: ["query"],
      },
    },
    {
      name: "proofpoint_quarantine_release",
      description:
        "⚠ HIGH-IMPACT. Release a quarantined message, delivering it to the intended recipient. " +
        "Irreversible delivery but message itself is preserved. Can deliver malicious mail to user. " +
        "Confirm with the user before invoking.",
      annotations: {
        title: "Release quarantined message (reversible)",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: "object" as const,
        properties: {
          message_id: {
            type: "string",
            description: "The quarantined message ID to release",
          },
        },
        required: ["message_id"],
      },
    },
    {
      name: "proofpoint_quarantine_delete",
      description:
        "⚠ DESTRUCTIVE — IRREVERSIBLE. Permanently delete a quarantined message. " +
        "This action cannot be undone and will remove the message from quarantine storage. " +
        "Confirm with the user before invoking.",
      annotations: {
        title: "Delete quarantined message (irreversible)",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: "object" as const,
        properties: {
          message_id: {
            type: "string",
            description: "The quarantined message ID to delete",
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
    case "proofpoint_quarantine_list": {
      const page = (args.page as number) || 1;
      const perPage = (args.per_page as number) || 50;

      // If no filters, elicit a recipient
      const hasFilters = args.sender || args.recipient || args.subject || args.folder;
      if (!hasFilters) {
        const recipientFilter = await elicitText(
          "The quarantine can be large. Would you like to filter by recipient email address? Leave blank to list all.",
          "recipient",
          "Enter a recipient email address to filter by, or leave blank for all"
        );
        if (recipientFilter) {
          args = { ...args, recipient: recipientFilter };
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {
        page,
        per_page: perPage,
      };

      if (args.sender) params.sender = args.sender as string;
      if (args.recipient) params.recipient = args.recipient as string;
      if (args.subject) params.subject = args.subject as string;
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;
      if (args.folder) params.folder = args.folder as string;

      logger.info("API call: quarantine.list", params);

      const result = await apiRequest<unknown>("/v1/quarantine", { params });

      const messages = Array.isArray(result)
        ? result
        : (result as Record<string, unknown>)?.messages ?? result;

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ messages, page, per_page: perPage }, null, 2),
          },
        ],
      };
    }

    case "proofpoint_quarantine_search": {
      const query = args.query as string;
      if (!query) {
        return {
          content: [{ type: "text", text: "Error: query is required" }],
          isError: true,
        };
      }

      const params: Record<string, string | number | boolean | undefined> = {
        q: query,
        page: (args.page as number) || 1,
        per_page: (args.per_page as number) || 50,
      };
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;

      logger.info("API call: quarantine.search", params);

      const result = await apiRequest<unknown>("/v1/quarantine/search", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_quarantine_release": {
      const messageId = args.message_id as string;
      if (!messageId) {
        return {
          content: [{ type: "text", text: "Error: message_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: quarantine.release", { messageId });

      const result = await apiRequest<unknown>(
        `/v1/quarantine/${encodeURIComponent(messageId)}/release`,
        { method: "POST" }
      );

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { success: true, message: `Message ${messageId} released successfully`, result },
              null,
              2
            ),
          },
        ],
      };
    }

    case "proofpoint_quarantine_delete": {
      const messageId = args.message_id as string;
      if (!messageId) {
        return {
          content: [{ type: "text", text: "Error: message_id is required" }],
          isError: true,
        };
      }

      // Confirm destructive action
      const confirmed = await elicitConfirmation(
        `Are you sure you want to permanently delete quarantined message ${messageId}? This cannot be undone.`
      );
      if (confirmed === false) {
        return {
          content: [{ type: "text", text: "Delete cancelled by user." }],
        };
      }

      logger.info("API call: quarantine.delete", { messageId });

      const result = await apiRequest<unknown>(
        `/v1/quarantine/${encodeURIComponent(messageId)}`,
        { method: "DELETE" }
      );

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { success: true, message: `Message ${messageId} deleted successfully`, result },
              null,
              2
            ),
          },
        ],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown quarantine tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const quarantineHandler: DomainHandler = {
  getTools,
  handleCall,
};
