/**
 * DLP (Data Loss Prevention) and Encryption domain handler
 *
 * Provides tools for Proofpoint Email DLP and encryption:
 * - List DLP incidents
 * - Get DLP incident details
 * - List encrypted messages
 *
 * API Reference: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/DLP
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitSelection } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_dlp_list_incidents",
      description:
        "List DLP incidents. Returns messages that triggered DLP rules, including policy violations and sensitive data detections.",
      inputSchema: {
        type: "object" as const,
        properties: {
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
          },
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description: "Filter by severity level",
          },
          status: {
            type: "string",
            enum: ["open", "resolved", "false_positive"],
            description: "Filter by incident status",
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
      name: "proofpoint_dlp_get_incident",
      description:
        "Get detailed information about a specific DLP incident, including matched rules, sensitive data types, and message metadata.",
      inputSchema: {
        type: "object" as const,
        properties: {
          incident_id: {
            type: "string",
            description: "The DLP incident ID",
          },
        },
        required: ["incident_id"],
      },
    },
    {
      name: "proofpoint_dlp_list_encrypted",
      description:
        "List messages that were encrypted by Proofpoint Email Encryption. Shows encrypted message status and recipient access.",
      inputSchema: {
        type: "object" as const,
        properties: {
          startDate: {
            type: "string",
            description: "Start date in ISO 8601 format",
          },
          endDate: {
            type: "string",
            description: "End date in ISO 8601 format",
          },
          sender: {
            type: "string",
            description: "Filter by sender email address",
          },
          recipient: {
            type: "string",
            description: "Filter by recipient email address",
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
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_dlp_list_incidents": {
      // If no filters, elicit a time range
      const hasFilters = args.startDate || args.severity || args.status;
      if (!hasFilters) {
        const range = await elicitSelection(
          "No filters specified. What time range would you like for DLP incidents?",
          "timeRange",
          [
            { value: "today", label: "Today" },
            { value: "past_week", label: "Past Week" },
            { value: "past_month", label: "Past Month" },
          ]
        );
        if (range) {
          const now = new Date();
          if (range === "today") {
            args = { ...args, startDate: now.toISOString().split("T")[0] };
          } else if (range === "past_week") {
            now.setDate(now.getDate() - 7);
            args = { ...args, startDate: now.toISOString().split("T")[0] };
          } else if (range === "past_month") {
            now.setMonth(now.getMonth() - 1);
            args = { ...args, startDate: now.toISOString().split("T")[0] };
          }
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {
        page: (args.page as number) || 1,
        per_page: (args.per_page as number) || 50,
      };
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;
      if (args.severity) params.severity = args.severity as string;
      if (args.status) params.status = args.status as string;

      logger.info("API call: dlp.listIncidents", params);

      const result = await apiRequest<unknown>("/v1/dlp/incidents", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_dlp_get_incident": {
      const incidentId = args.incident_id as string;
      if (!incidentId) {
        return {
          content: [{ type: "text", text: "Error: incident_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: dlp.getIncident", { incidentId });

      const result = await apiRequest<unknown>(
        `/v1/dlp/incidents/${encodeURIComponent(incidentId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_dlp_list_encrypted": {
      const params: Record<string, string | number | boolean | undefined> = {
        page: (args.page as number) || 1,
        per_page: (args.per_page as number) || 50,
      };
      if (args.startDate) params.startDate = args.startDate as string;
      if (args.endDate) params.endDate = args.endDate as string;
      if (args.sender) params.sender = args.sender as string;
      if (args.recipient) params.recipient = args.recipient as string;

      logger.info("API call: dlp.listEncrypted", params);

      const result = await apiRequest<unknown>("/v1/encryption/messages", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown DLP tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const dlpHandler: DomainHandler = {
  getTools,
  handleCall,
};
