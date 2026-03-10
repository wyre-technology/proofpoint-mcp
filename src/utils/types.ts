/**
 * Shared types for the Proofpoint MCP server
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Tool call result type - inline definition for MCP SDK compatibility
 */
export type CallToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

/**
 * Domain handler interface
 */
export interface DomainHandler {
  /** Get the tools for this domain */
  getTools(): Tool[];
  /** Handle a tool call */
  handleCall(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<CallToolResult>;
}

/**
 * Domain names for Proofpoint
 *
 * - tap: Targeted Attack Protection (SIEM API) - threats, clicks, messages
 * - quarantine: Quarantine management - list, release, delete, search
 * - threat_intel: Threat intelligence - IOCs, threat families, campaigns
 * - dlp: Email DLP and encryption
 * - people: User risk scoring and Very Attacked People (VAP) reports
 * - forensics: Forensics and threat response - auto-pull, search & destroy
 * - smart_search: Message tracing / Smart Search
 * - policy: Policy management
 * - url_defense: URL decoding and analysis
 * - events: Spam/phishing/malware detection events
 * - reports: Organization-level security reports
 */
export type DomainName =
  | "tap"
  | "quarantine"
  | "threat_intel"
  | "dlp"
  | "people"
  | "forensics"
  | "smart_search"
  | "policy"
  | "url_defense"
  | "events"
  | "reports";

const VALID_DOMAINS: DomainName[] = [
  "tap",
  "quarantine",
  "threat_intel",
  "dlp",
  "people",
  "forensics",
  "smart_search",
  "policy",
  "url_defense",
  "events",
  "reports",
];

/**
 * Check if a string is a valid domain name
 */
export function isDomainName(value: string): value is DomainName {
  return VALID_DOMAINS.includes(value as DomainName);
}

/**
 * Get all valid domain names
 */
export function getAllDomainNames(): DomainName[] {
  return [...VALID_DOMAINS];
}

/**
 * Proofpoint credentials extracted from environment or gateway headers.
 *
 * Proofpoint uses HTTP Basic Auth with a service principal + secret
 * for most API endpoints.
 */
export interface ProofpointCredentials {
  /** Service principal (username) for API authentication */
  servicePrincipal: string;
  /** Service secret (password) for API authentication */
  serviceSecret: string;
  /** Base URL for the Proofpoint API (region-specific) */
  baseUrl: string;
}
