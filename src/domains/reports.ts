/**
 * Reports domain handler
 *
 * Provides tools for Proofpoint organization-level security reports:
 * - Get organization overview/summary
 * - Get threat summary report
 * - Get mail flow report
 * - Get executive summary
 *
 * API Reference: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/Reports
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { DomainHandler, CallToolResult } from "../utils/types.js";
import { apiRequest } from "../utils/client.js";
import { logger } from "../utils/logger.js";
import { elicitSelection } from "../utils/elicitation.js";

function getTools(): Tool[] {
  return [
    {
      name: "proofpoint_reports_org_summary",
      description:
        "Get organization security summary. Returns high-level metrics: total messages processed, threats blocked, quarantined, and delivered.",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [1, 7, 14, 30, 90],
            description: "Time window in days (default: 30)",
          },
        },
      },
    },
    {
      name: "proofpoint_reports_threat_summary",
      description:
        "Get threat summary report. Breakdown of threats by type (spam, phishing, malware, impostor) with counts and trends.",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [1, 7, 14, 30, 90],
            description: "Time window in days (default: 30)",
          },
          threatType: {
            type: "string",
            enum: ["spam", "phish", "malware", "impostor", "all"],
            description: "Focus on a specific threat type (default: all)",
          },
        },
      },
    },
    {
      name: "proofpoint_reports_mail_flow",
      description:
        "Get mail flow report. Shows email volume over time with breakdown by disposition (delivered, blocked, quarantined).",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [1, 7, 14, 30, 90],
            description: "Time window in days (default: 7)",
          },
          granularity: {
            type: "string",
            enum: ["hourly", "daily", "weekly"],
            description: "Data point granularity (default: daily)",
          },
        },
      },
    },
    {
      name: "proofpoint_reports_executive_summary",
      description:
        "Get executive summary report. High-level security posture overview suitable for management reporting. Includes threat trends, top targeted users, and effectiveness metrics.",
      inputSchema: {
        type: "object" as const,
        properties: {
          window: {
            type: "number",
            enum: [7, 14, 30, 90],
            description: "Time window in days (default: 30)",
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
    case "proofpoint_reports_org_summary": {
      let window = (args.window as number) || 30;

      if (!args.window) {
        const selected = await elicitSelection(
          "What time window would you like for the organization summary?",
          "window",
          [
            { value: "1", label: "Last 24 hours" },
            { value: "7", label: "Last 7 days" },
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
      };

      logger.info("API call: reports.orgSummary", params);

      const result = await apiRequest<unknown>("/v1/reports/summary", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_reports_threat_summary": {
      const window = (args.window as number) || 30;
      const params: Record<string, string | number | boolean | undefined> = {
        window,
      };
      if (args.threatType && args.threatType !== "all") {
        params.threatType = args.threatType as string;
      }

      logger.info("API call: reports.threatSummary", params);

      const result = await apiRequest<unknown>("/v1/reports/threats", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_reports_mail_flow": {
      const window = (args.window as number) || 7;
      const params: Record<string, string | number | boolean | undefined> = {
        window,
      };
      if (args.granularity) params.granularity = args.granularity as string;

      logger.info("API call: reports.mailFlow", params);

      const result = await apiRequest<unknown>("/v1/reports/mail-flow", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "proofpoint_reports_executive_summary": {
      const window = (args.window as number) || 30;
      const params: Record<string, string | number | boolean | undefined> = {
        window,
      };

      logger.info("API call: reports.executiveSummary", params);

      const result = await apiRequest<unknown>("/v1/reports/executive", { params });

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown reports tool: ${toolName}` }],
        isError: true,
      };
  }
}

export const reportsHandler: DomainHandler = {
  getTools,
  handleCall,
};
