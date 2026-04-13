/**
 * Proofpoint HTTP client and credential management.
 *
 * Proofpoint APIs use HTTP Basic Auth with a service principal + secret.
 *
 * In gateway mode (AUTH_MODE=gateway), credentials are passed per-request
 * via AsyncLocalStorage to avoid cross-tenant leakage under concurrent load.
 *
 * In env mode (AUTH_MODE=env or unset), credentials come from
 * PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET environment variables.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { logger } from "./logger.js";
import type { ProofpointCredentials } from "./types.js";

/**
 * Default Proofpoint API base URL.
 * Can be overridden via PROOFPOINT_BASE_URL env var for different regions or on-prem.
 */
const DEFAULT_BASE_URL = "https://tap-api-v2.proofpoint.com";

/**
 * Per-request credential store for gateway mode.
 * Ensures concurrent requests cannot leak credentials across tenants.
 */
const credentialStore = new AsyncLocalStorage<ProofpointCredentials>();

/**
 * Run a callback with per-request credential overrides.
 * Used by the HTTP transport in gateway mode.
 */
export function runWithCredentials<T>(creds: ProofpointCredentials, fn: () => T): T {
  return credentialStore.run(creds, fn);
}

/**
 * Get credentials — checks per-request store first, then falls back to env vars.
 */
export function getCredentials(): ProofpointCredentials | null {
  // Per-request override (gateway mode)
  const override = credentialStore.getStore();
  if (override) {
    return override;
  }

  // Fallback to environment variables (stdio / env mode)
  const servicePrincipal = process.env.PROOFPOINT_SERVICE_PRINCIPAL;
  const serviceSecret = process.env.PROOFPOINT_SERVICE_SECRET;

  if (!servicePrincipal || !serviceSecret) {
    logger.warn("Missing credentials", {
      hasServicePrincipal: !!servicePrincipal,
      hasServiceSecret: !!serviceSecret,
    });
    return null;
  }

  return {
    servicePrincipal,
    serviceSecret,
    baseUrl: process.env.PROOFPOINT_BASE_URL || DEFAULT_BASE_URL,
  };
}

/**
 * Build the Basic Auth header value from credentials.
 */
function buildBasicAuth(creds: ProofpointCredentials): string {
  const encoded = Buffer.from(
    `${creds.servicePrincipal}:${creds.serviceSecret}`
  ).toString("base64");
  return `Basic ${encoded}`;
}

/**
 * Make an authenticated HTTP request to the Proofpoint API.
 * Reads credentials fresh from env on each call so gateway mode
 * header injection is always reflected.
 */
export async function apiRequest<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    params?: Record<string, string | number | boolean | undefined>;
    /** Override the base URL for this request (e.g., for different Proofpoint API hosts) */
    baseUrl?: string;
  } = {}
): Promise<T> {
  const creds = getCredentials();
  if (!creds) {
    throw new Error(
      "No Proofpoint API credentials configured. Please set PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET environment variables."
    );
  }

  const base = options.baseUrl || creds.baseUrl;
  const url = new URL(path, base);

  if (options.params) {
    for (const [key, value] of Object.entries(options.params)) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const method = options.method || "GET";
  const headers: Record<string, string> = {
    Authorization: buildBasicAuth(creds),
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const fetchOptions: RequestInit = {
    method,
    headers,
  };

  if (options.body !== undefined && method !== "GET") {
    fetchOptions.body = JSON.stringify(options.body);
  }

  logger.debug("Proofpoint API request", { method, url: url.toString() });

  const response = await fetch(url.toString(), fetchOptions);

  // Safe: read text once, then try JSON parse
  const rawText = await response.text();
  let responseBody: unknown;
  try {
    responseBody = JSON.parse(rawText);
  } catch {
    responseBody = rawText;
  }

  if (!response.ok) {
    const message =
      typeof responseBody === "object" &&
      responseBody !== null &&
      "message" in responseBody
        ? String((responseBody as Record<string, unknown>).message)
        : `HTTP ${response.status}: ${response.statusText}`;

    logger.error("Proofpoint API error", {
      status: response.status,
      url: url.toString(),
      message,
    });

    if (response.status === 401) {
      throw new Error(
        `Authentication failed: ${message}. Check your PROOFPOINT_SERVICE_PRINCIPAL and PROOFPOINT_SERVICE_SECRET.`
      );
    }
    if (response.status === 403) {
      throw new Error(`Forbidden: ${message}. Insufficient permissions.`);
    }
    if (response.status === 404) {
      throw new Error(`Not found: ${message}`);
    }
    if (response.status === 429) {
      throw new Error(
        `Rate limit exceeded: ${message}. Please retry after a moment.`
      );
    }
    throw new Error(`Proofpoint API error (${response.status}): ${message}`);
  }

  return responseBody as T;
}

/**
 * Clear cached credentials (useful for testing)
 */
export function clearCredentials(): void {
  // No-op for now; credentials are read fresh from env each time
}
