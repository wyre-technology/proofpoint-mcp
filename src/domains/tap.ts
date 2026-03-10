/**
 * TAP (Targeted Attack Protection) domain handler
 *
 * Provides tools for the Proofpoint TAP SIEM API:
 * - Get all threats (messages delivered/blocked with threats)
 * - Get all clicks (permitted/blocked clicks on threat URLs)
 * - Get messages delivered containing threats
 * - Get messages blocked containing threats
 * - Get clicks permitted on threat URLs
 * - Get clicks blocked on threat URLs
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitSelection } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_tap_get_all_threats",
      description:
        "Get all threats (messages and clicks) from the TAP SIEM API for a given time window. Returns both delivered/blocked messages and permitted/blocked clicks.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description:
              "Number of seconds ago to fetch threats from (max 3600). Mutually exclusive with sinceTime/interval.",
          },
          sinceTime: {
            type: "string",
            description:
              "ISO 8601 date/time to fetch threats since. Mutually exclusive with sinceSeconds/interval.",
          },
          interval: {
            type: "string",
            description:
              'Predefined time interval: "PT30M" (30 min) or "PT1H" (1 hour). Mutually exclusive with sinceSeconds/sinceTime.',
          },
          threatStatus: {
            type: "string",
            enum: ["active", "cleared", "falsePositive"],
            description:
              "Filter by threat status (default: active)",
          },
          format: {
            type: "string",
            enum: ["json", "syslog"],
            description: "Response format (default: json)",
          },
        },
      },
    },
    {
      name: "proofpoint_tap_get_messages_delivered",
      description:
        "Get messages delivered containing threats. These are messages that reached the recipient's mailbox despite containing identified threats.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threatStatus: {
            type: "string",
            enum: ["active", "cleared", "falsePositive"],
            description: "Filter by threat status",
          },
        },
      },
    },
    {
      name: "proofpoint_tap_get_messages_blocked",
      description:
        "Get messages blocked that contained threats. These are messages quarantined or rejected before reaching the recipient.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threatStatus: {
            type: "string",
            enum: ["active", "cleared", "falsePositive"],
            description: "Filter by threat status",
          },
        },
      },
    },
    {
      name: "proofpoint_tap_get_clicks_permitted",
      description:
        "Get permitted clicks on threat URLs. These are clicks that were allowed through to the destination.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threatStatus: {
            type: "string",
            enum: ["active", "cleared", "falsePositive"],
            description: "Filter by threat status",
          },
        },
      },
    },
    {
      name: "proofpoint_tap_get_clicks_blocked",
      description:
        "Get blocked clicks on threat URLs. These are clicks that were prevented from reaching the malicious destination.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threatStatus: {
            type: "string",
            enum: ["active", "cleared", "falsePositive"],
            description: "Filter by threat status",
          },
        },
      },
    },
  ];
}

/**
 * Build common TAP SIEM query parameters from tool args.
 */
function buildTapParams(
  args: Record<string, unknown>
): Record<string, string | number | boolean | undefined> {
  const params: Record<string, string | number | boolean | undefined> = {};

  if (args.sinceSeconds) params.sinceSeconds = args.sinceSeconds as number;
  if (args.sinceTime) params.sinceTime = args.sinceTime as string;
  if (args.interval) params.interval = args.interval as string;
  if (args.threatStatus) params.threatStatus = args.threatStatus as string;
  if (args.format) params.format = args.format as string;

  return params;
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_tap_get_all_threats": {
      // If no time filter, elicit a time range
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        const range = await elicitSelection(
          "No time window specified. TAP SIEM API requires a time parameter. What range would you like?",
          "timeRange",
          [
            { value: "PT30M", label: "Last 30 minutes" },
            { value: "PT1H", label: "Last 1 hour" },
          ]
        );
        if (range) {
          args = { ...args, interval: range };
        } else {
          // Default to last hour if elicitation not available
          args = { ...args, interval: "PT1H" };
        }
      }

      const params = buildTapParams(args);
      logger.info("API call: tap.getAllThreats", params);

      const result = await apiRequest<unknown>("/v2/siem/all", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_tap_get_messages_delivered": {
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        args = { ...args, interval: "PT1H" };
      }
      const params = buildTapParams(args);
      logger.info("API call: tap.getMessagesDelivered", params);

      const result = await apiRequest<unknown>("/v2/siem/messages/delivered", {
        params,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_tap_get_messages_blocked": {
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        args = { ...args, interval: "PT1H" };
      }
      const params = buildTapParams(args);
      logger.info("API call: tap.getMessagesBlocked", params);

      const result = await apiRequest<unknown>("/v2/siem/messages/blocked", {
        params,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_tap_get_clicks_permitted": {
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        args = { ...args, interval: "PT1H" };
      }
      const params = buildTapParams(args);
      logger.info("API call: tap.getClicksPermitted", params);

      const result = await apiRequest<unknown>("/v2/siem/clicks/permitted", {
        params,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_tap_get_clicks_blocked": {
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        args = { ...args, interval: "PT1H" };
      }
      const params = buildTapParams(args);
      logger.info("API call: tap.getClicksBlocked", params);

      const result = await apiRequest<unknown>("/v2/siem/clicks/blocked", {
        params,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown TAP tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const tapHandler: DomainHandler = {
  getTools,
  handleCall,
};
