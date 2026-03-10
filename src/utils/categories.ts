/**
 * Tool categories for lazy-loading meta-tools mode.
 *
 * Each category maps to a domain and lists the tool names it exposes.
 * This allows LLM clients to discover tools without loading all domains upfront.
 */

import type { DomainName } from "./types.js";

export interface ToolCategory {
  description: string;
  domain: DomainName;
  tools: string[];
}

export const TOOL_CATEGORIES: Record<string, ToolCategory> = {
  tap: {
    description:
      "Targeted Attack Protection - threats, messages, clicks via SIEM API",
    domain: "tap",
    tools: [
      "proofpoint_tap_get_all_threats",
      "proofpoint_tap_get_messages_delivered",
      "proofpoint_tap_get_messages_blocked",
      "proofpoint_tap_get_clicks_permitted",
      "proofpoint_tap_get_clicks_blocked",
    ],
  },
  quarantine: {
    description:
      "Quarantine management - list, search, release, delete quarantined messages",
    domain: "quarantine",
    tools: [
      "proofpoint_quarantine_list",
      "proofpoint_quarantine_search",
      "proofpoint_quarantine_release",
      "proofpoint_quarantine_delete",
    ],
  },
  threat_intel: {
    description:
      "Threat intelligence - campaigns, threat details, families, IOCs",
    domain: "threat_intel",
    tools: [
      "proofpoint_threat_get_campaign",
      "proofpoint_threat_get_by_id",
      "proofpoint_threat_list_families",
      "proofpoint_threat_get_iocs",
    ],
  },
  dlp: {
    description: "Email DLP and encryption - incidents and encrypted messages",
    domain: "dlp",
    tools: [
      "proofpoint_dlp_list_incidents",
      "proofpoint_dlp_get_incident",
      "proofpoint_dlp_list_encrypted",
    ],
  },
  people: {
    description:
      "User risk scoring - Very Attacked People, top clickers, risk scores",
    domain: "people",
    tools: [
      "proofpoint_people_get_vap",
      "proofpoint_people_get_top_clickers",
      "proofpoint_people_get_user_risk",
    ],
  },
  forensics: {
    description:
      "Forensics and threat response - threat/campaign forensics, search & destroy",
    domain: "forensics",
    tools: [
      "proofpoint_forensics_get_threat",
      "proofpoint_forensics_get_campaign",
      "proofpoint_forensics_search_messages",
      "proofpoint_forensics_pull_messages",
    ],
  },
  smart_search: {
    description: "Message tracing - trace messages, get details and headers",
    domain: "smart_search",
    tools: [
      "proofpoint_smart_search_trace",
      "proofpoint_smart_search_get_message",
      "proofpoint_smart_search_get_headers",
    ],
  },
  policy: {
    description: "Policy management - list policies, details, routing rules",
    domain: "policy",
    tools: [
      "proofpoint_policy_list",
      "proofpoint_policy_get",
      "proofpoint_policy_list_routes",
    ],
  },
  url_defense: {
    description: "URL decoding and analysis - decode rewritten URLs, analyze threats",
    domain: "url_defense",
    tools: ["proofpoint_url_decode", "proofpoint_url_analyze"],
  },
  events: {
    description:
      "Detection events - spam, phishing, malware detections and statistics",
    domain: "events",
    tools: [
      "proofpoint_events_list",
      "proofpoint_events_get_details",
      "proofpoint_events_get_stats",
    ],
  },
  reports: {
    description:
      "Organization reports - org summary, threat summary, mail flow, executive summary",
    domain: "reports",
    tools: [
      "proofpoint_reports_org_summary",
      "proofpoint_reports_threat_summary",
      "proofpoint_reports_mail_flow",
      "proofpoint_reports_executive_summary",
    ],
  },
};

/**
 * Build a map from tool name to category name for fast lookup.
 */
export function buildToolToCategoryMap(): Map<string, string> {
  const map = new Map<string, string>();
  for (const [categoryName, category] of Object.entries(TOOL_CATEGORIES)) {
    for (const tool of category.tools) {
      map.set(tool, categoryName);
    }
  }
  return map;
}

/**
 * Simple keyword-based intent router.
 * Returns category names sorted by relevance (number of keyword matches).
 */
export function routeIntent(intent: string): string[] {
  const keywords = intent.toLowerCase().split(/\s+/);

  const scores: Array<{ category: string; score: number }> = [];

  for (const [name, category] of Object.entries(TOOL_CATEGORIES)) {
    const searchText =
      `${name} ${category.description} ${category.tools.join(" ")}`.toLowerCase();

    let score = 0;
    for (const keyword of keywords) {
      if (searchText.includes(keyword)) {
        score++;
      }
    }

    if (score > 0) {
      scores.push({ category: name, score });
    }
  }

  scores.sort((a, b) => b.score - a.score);
  return scores.map((s) => s.category);
}
