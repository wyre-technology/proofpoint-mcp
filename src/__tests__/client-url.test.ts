/**
 * Request URL construction regression tests.
 *
 * `apiRequest` used to build URLs with `new URL(path, base)`, which is RFC 3986
 * relative resolution rather than concatenation: a path-absolute reference like
 * "/v2/campaign" replaces the base's entire path. That silently dropped the
 * "/api" prefix Proofpoint Essentials tenants require, and was invisible against
 * the default enterprise host because it has no path segment.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiRequest } from "../utils/client.js";

/** Stub global fetch and hand back the URL the next request is sent to. */
function captureFetchedUrl(): () => string {
  let seen = "";
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      seen = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve("{}"),
      } as Response);
    })
  );
  return () => seen;
}

describe("apiRequest URL construction", () => {
  beforeEach(() => {
    process.env.PROOFPOINT_SERVICE_PRINCIPAL = "principal";
    process.env.PROOFPOINT_SERVICE_SECRET = "secret";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.PROOFPOINT_SERVICE_PRINCIPAL;
    delete process.env.PROOFPOINT_SERVICE_SECRET;
    delete process.env.PROOFPOINT_BASE_URL;
  });

  it.each([
    // [description, baseUrl, expected URL]
    [
      "enterprise host without a path segment",
      "https://tap-api-v2.proofpoint.com",
      "https://tap-api-v2.proofpoint.com/v2/campaign",
    ],
    [
      "Essentials host whose path prefix must survive",
      "https://tenant.proofpointessentials.com/api/",
      "https://tenant.proofpointessentials.com/api/v2/campaign",
    ],
    [
      "path prefix without a trailing slash",
      "https://tenant.proofpointessentials.com/api",
      "https://tenant.proofpointessentials.com/api/v2/campaign",
    ],
    [
      "redundant trailing slashes",
      "https://tap-api-v2.proofpoint.com//",
      "https://tap-api-v2.proofpoint.com/v2/campaign",
    ],
  ])("preserves the base path for a %s", async (_name, baseUrl, expected) => {
    const fetchedUrl = captureFetchedUrl();
    await apiRequest("/v2/campaign", { baseUrl });
    expect(fetchedUrl()).toBe(expected);
  });

  it("reads the base URL from PROOFPOINT_BASE_URL when not overridden", async () => {
    process.env.PROOFPOINT_BASE_URL = "https://tenant.proofpointessentials.com/api/";
    const fetchedUrl = captureFetchedUrl();
    await apiRequest("/v2/threat/summary/abc");
    expect(fetchedUrl()).toBe(
      "https://tenant.proofpointessentials.com/api/v2/threat/summary/abc"
    );
  });

  it("appends query params after the joined path", async () => {
    const fetchedUrl = captureFetchedUrl();
    await apiRequest("/v2/people/vap", {
      baseUrl: "https://tenant.proofpointessentials.com/api/",
      params: { window: 30, undefinedIsSkipped: undefined },
    });
    expect(fetchedUrl()).toBe(
      "https://tenant.proofpointessentials.com/api/v2/people/vap?window=30"
    );
  });
});
