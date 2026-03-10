/**
 * Events domain handler
 *
 * Provides tools for Proofpoint spam/phishing/malware detection events:
 * - List recent detection events
 * - Get event details
 * - Get detection statistics
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitSelection } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_events_list",
      description:
        "List spam, phishing, and malware detection events. Returns events where Proofpoint detected and acted on threats.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago to fetch events from (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to fetch events since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
          },
          threatType: {
            type: "string",
            enum: ["spam", "phish", "malware", "impostor"],
            description: "Filter by threat type",
          },
          disposition: {
            type: "string",
            enum: ["delivered", "blocked", "quarantined"],
            description: "Filter by disposition (what happened to the message)",
          },
        },
      },
    },
    {
      name: "proofpoint_events_get_details",
      description:
        "Get detailed information about a specific detection event, including full threat analysis and message metadata.",
      inputSchema: {
        type: "object" as const,
        properties: {
          event_id: {
            type: "string",
            description: "The event ID to look up",
          },
        },
        required: ["event_id"],
      },
    },
    {
      name: "proofpoint_events_get_stats",
      description:
        "Get detection event statistics. Returns counts of spam, phishing, malware, and impostor detections over a time period.",
      inputSchema: {
        type: "object" as const,
        properties: {
          sinceSeconds: {
            type: "number",
            description: "Number of seconds ago (max 3600)",
          },
          sinceTime: {
            type: "string",
            description: "ISO 8601 date/time to get stats since",
          },
          interval: {
            type: "string",
            description: 'Predefined interval: "PT30M" or "PT1H"',
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
    case "proofpoint_events_list": {
      // If no time filter, elicit
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        const range = await elicitSelection(
          "No time window specified. What range would you like for detection events?",
          "timeRange",
          [
            { value: "PT30M", label: "Last 30 minutes" },
            { value: "PT1H", label: "Last 1 hour" },
          ]
        );
        if (range) {
          args = { ...args, interval: range };
        } else {
          args = { ...args, interval: "PT1H" };
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.sinceSeconds) params.sinceSeconds = args.sinceSeconds as number;
      if (args.sinceTime) params.sinceTime = args.sinceTime as string;
      if (args.interval) params.interval = args.interval as string;
      if (args.threatType) params.threatType = args.threatType as string;
      if (args.disposition) params.disposition = args.disposition as string;

      logger.info("API call: events.list", params);

      const result = await apiRequest<unknown>("/v2/siem/all", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_events_get_details": {
      const eventId = args.event_id as string;
      if (!eventId) {
        return {
          content: [{ type: "text", text: "Error: event_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: events.getDetails", { eventId });

      const result = await apiRequest<unknown>(
        `/v2/events/${encodeURIComponent(eventId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_events_get_stats": {
      if (!args.sinceSeconds && !args.sinceTime && !args.interval) {
        args = { ...args, interval: "PT1H" };
      }

      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.sinceSeconds) params.sinceSeconds = args.sinceSeconds as number;
      if (args.sinceTime) params.sinceTime = args.sinceTime as string;
      if (args.interval) params.interval = args.interval as string;

      logger.info("API call: events.getStats", params);

      const result = await apiRequest<unknown>("/v2/events/stats", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown events tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const eventsHandler: DomainHandler = {
  getTools,
  handleCall,
};
