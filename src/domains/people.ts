/**
 * People domain handler
 *
 * Provides tools for Proofpoint user risk and Very Attacked People (VAP) reports:
 * - Get Very Attacked People (VAP) report
 * - Get top clickers
 * - Get user risk scores
 *
 * API Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/People_API
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitSelection } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_people_get_vap",
      description:
        "Get the Very Attacked People (VAP) report. Returns users who received the most attacks, ranked by attack index. Useful for identifying high-risk users.",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [14, 30, 90],
            description: "Time window in days: 14, 30, or 90 (default: 30)",
          },
          page: {
            type: "number",
            description: "Page number (default: 1)",
          },
          size: {
            type: "number",
            description: "Results per page (default: 1000)",
          },
        },
      },
    },
    {
      name: "proofpoint_people_get_top_clickers",
      description:
        "Get top clickers report. Returns users who clicked on the most threat URLs, indicating users who may need additional security training.",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [14, 30, 90],
            description: "Time window in days: 14, 30, or 90 (default: 30)",
          },
          page: {
            type: "number",
            description: "Page number (default: 1)",
          },
          size: {
            type: "number",
            description: "Results per page (default: 1000)",
          },
        },
      },
    },
    {
      name: "proofpoint_people_get_user_risk",
      description:
        "Get the risk score and attack details for a specific user by email address.",
      inputSchema: {
        type: "object" as const,
        properties: {
          email: {
            type: "string",
            description: "User email address to look up",
          },
          window: {
            type: "number",
            enum: [14, 30, 90],
            description: "Time window in days (default: 30)",
          },
        },
        required: ["email"],
      },
    },
  ];
}

async function handleCall(
  toolName: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  switch (toolName) {
    case "proofpoint_people_get_vap": {
      let window = (args.window as number) || 30;

      // Elicit time window if not specified
      if (!args.window) {
        const selected = await elicitSelection(
          "What time window would you like for the VAP report?",
          "window",
          [
            { value: "14", label: "Last 14 days" },
            { value: "30", label: "Last 30 days" },
            { value: "90", label: "Last 90 days" },
          ]
        );
        if (selected) {
          window = parseInt(selected, 10);
        }
      }

      const params: Record<string, string | number | boolean | undefined> = {
        window,
        page: (args.page as number) || 1,
        size: (args.size as number) || 1000,
      };

      logger.info("API call: people.getVAP", params);

      const result = await apiRequest<unknown>("/v2/people/vap", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_people_get_top_clickers": {
      const window = (args.window as number) || 30;
      const params: Record<string, string | number | boolean | undefined> = {
        window,
        page: (args.page as number) || 1,
        size: (args.size as number) || 1000,
      };

      logger.info("API call: people.getTopClickers", params);

      const result = await apiRequest<unknown>("/v2/people/top-clickers", {
        params,
      });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_people_get_user_risk": {
      const email = args.email as string;
      if (!email) {
        return {
          content: [{ type: "text", text: "Error: email is required" }],
          isError: true,
        };
      }

      const window = (args.window as number) || 30;
      const params: Record<string, string | number | boolean | undefined> = {
        window,
      };

      logger.info("API call: people.getUserRisk", { email, window });

      const result = await apiRequest<unknown>(
        `/v2/people/${encodeURIComponent(email)}`,
        { params }
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown people tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const peopleHandler: DomainHandler = {
  getTools,
  handleCall,
};
