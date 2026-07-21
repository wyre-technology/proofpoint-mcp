/**
 * Gateway-mode credential resolution.
 *
 * X-Proofpoint-Cluster-Url was sent by the gateway but never read here —
 * `startHttpTransport` hardcoded `baseUrl` from `PROOFPOINT_BASE_URL` /
 * the default TAP host regardless of what the customer's stored credential
 * actually carried, so any tenant needing a non-default host (Proofpoint
 * Essentials, EU hosting) silently hit the wrong API.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolveGatewayCredentials } from "../utils/client.js";

describe("resolveGatewayCredentials", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PROOFPOINT_BASE_URL;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  function headerGetter(headers: Record<string, string>) {
    return (name: string) => headers[name];
  }

  it("uses X-Proofpoint-Cluster-Url as baseUrl when present", () => {
    const result = resolveGatewayCredentials(
      headerGetter({
        "x-proofpoint-service-principal": "principal-1",
        "x-proofpoint-service-secret": "secret-1",
        "x-proofpoint-cluster-url": "https://tenant.proofpointessentials.com/api",
      })
    );
    expect(result.credentials).toEqual({
      servicePrincipal: "principal-1",
      serviceSecret: "secret-1",
      baseUrl: "https://tenant.proofpointessentials.com/api",
    });
  });

  it("falls back to PROOFPOINT_BASE_URL when the header is absent", () => {
    process.env.PROOFPOINT_BASE_URL = "https://tap-api-v2-eu.proofpoint.com";
    const result = resolveGatewayCredentials(
      headerGetter({
        "x-proofpoint-service-principal": "principal-1",
        "x-proofpoint-service-secret": "secret-1",
      })
    );
    expect(result.credentials?.baseUrl).toBe("https://tap-api-v2-eu.proofpoint.com");
  });

  it("falls back to the default TAP host when neither is set", () => {
    const result = resolveGatewayCredentials(
      headerGetter({
        "x-proofpoint-service-principal": "principal-1",
        "x-proofpoint-service-secret": "secret-1",
      })
    );
    expect(result.credentials?.baseUrl).toBe("https://tap-api-v2.proofpoint.com");
  });

  it("errors when servicePrincipal or serviceSecret is missing", () => {
    expect(resolveGatewayCredentials(headerGetter({ "x-proofpoint-service-secret": "s" })).error).toMatch(
      /X-Proofpoint-Service-Principal/
    );
    expect(resolveGatewayCredentials(headerGetter({ "x-proofpoint-service-principal": "p" })).error).toMatch(
      /X-Proofpoint-Service-Secret/
    );
  });
});
