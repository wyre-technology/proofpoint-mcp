/**
 * Policy domain handler
 *
 * Provides tools for Proofpoint policy management:
 * - List email security policies
 * - Get policy details
 * - List policy routes/rules
 *
 * API Reference: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/Policies
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_policy_list",
      description:
        "List all email security policies. Returns policy names, types, and enabled status.",
      inputSchema: {
        type: "object" as const,
        properties: {
          type: {
            type: "string",
            enum: ["inbound", "outbound", "internal"],
            description: "Filter by policy direction",
          },
        },
      },
    },
    {
      name: "proofpoint_policy_get",
      description:
        "Get detailed information about a specific policy including rules, conditions, and actions.",
      inputSchema: {
        type: "object" as const,
        properties: {
          policy_id: {
            type: "string",
            description: "The policy ID to retrieve",
          },
        },
        required: ["policy_id"],
      },
    },
    {
      name: "proofpoint_policy_list_routes",
      description:
        "List email routing rules/routes. Shows how mail is routed based on policy configuration.",
      inputSchema: {
        type: "object" as const,
        properties: {
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
    case "proofpoint_policy_list": {
      const params: Record<string, string | number | boolean | undefined> = {};
      if (args.type) params.type = args.type as string;

      logger.info("API call: policy.list", params);

      const result = await apiRequest<unknown>("/v1/policies", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_policy_get": {
      const policyId = args.policy_id as string;
      if (!policyId) {
        return {
          content: [{ type: "text", text: "Error: policy_id is required" }],
          isError: true,
        };
      }

      logger.info("API call: policy.get", { policyId });

      const result = await apiRequest<unknown>(
        `/v1/policies/${encodeURIComponent(policyId)}`
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_policy_list_routes": {
      const params: Record<string, string | number | boolean | undefined> = {
        page: (args.page as number) || 1,
        per_page: (args.per_page as number) || 50,
      };

      logger.info("API call: policy.listRoutes", params);

      const result = await apiRequest<unknown>("/v1/policy/routes", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown policy tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const policyHandler: DomainHandler = {
  getTools,
  handleCall,
};
