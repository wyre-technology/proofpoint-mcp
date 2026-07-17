/**
 * MCP Apps (SEP-1865) contract tests — mirrors the checks an MCP Apps host
 * performs to render the threat card:
 *   1. renderable tools advertise the UI resource via _meta
 *   2. the ui:// resource lists and reads back as profile=mcp-app HTML
 *   3. buildThreatCard normalizes a TAP threat summary into the card payload
 *      the iframe renders from, best-effort (bad payloads drop the card)
 */

import { describe, it, expect, vi } from "vitest";
import { getAvailableDomains, getDomainHandler } from "../domains/index.js";
import { listResources, readResource } from "../resources.js";
import {
  buildThreatCard,
  applyBrandInjection,
  THREAT_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
} from "../card.builder.js";
import { THREAT_CARD_HTML } from "../generated/threat-card-html.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

const RENDERABLE_TOOLS = ["proofpoint_threat_get_by_id"];

async function getAllTools(): Promise<Tool[]> {
  const tools: Tool[] = [];
  for (const domain of getAvailableDomains()) {
    const handler = await getDomainHandler(domain);
    tools.push(...handler.getTools());
  }
  return tools;
}

describe("MCP Apps threat card", () => {
  describe("tool _meta advertisement", () => {
    it.each(RENDERABLE_TOOLS)("%s links the card via _meta", async (name) => {
      const tool = (await getAllTools()).find((t) => t.name === name);
      expect(tool).toBeDefined();
      // Canonical flat key (ext-apps RESOURCE_URI_META_KEY) …
      expect(tool?._meta?.["ui/resourceUri"]).toBe(THREAT_CARD_RESOURCE_URI);
      // … and the nested form registerAppTool also emits.
      expect((tool?._meta?.ui as { resourceUri?: string })?.resourceUri).toBe(
        THREAT_CARD_RESOURCE_URI
      );
    });

    it("no other tools carry UI metadata", async () => {
      const others = (await getAllTools()).filter(
        (t) => t._meta && !RENDERABLE_TOOLS.includes(t.name)
      );
      expect(others).toEqual([]);
    });
  });

  describe("ui:// resource", () => {
    it("is listed with the MCP Apps MIME type", () => {
      const card = listResources().find((r) => r.uri === THREAT_CARD_RESOURCE_URI);
      expect(card?.mimeType).toBe(MCP_APP_RESOURCE_MIME);
    });

    it("reads back as profile=mcp-app HTML containing the card app", () => {
      const content = readResource(THREAT_CARD_RESOURCE_URI);
      expect(content.mimeType).toBe(MCP_APP_RESOURCE_MIME);
      // No MCP_BRAND_* env set → the embedded HTML is served byte-identical.
      expect(content.text).toBe(THREAT_CARD_HTML);
      expect(content.text).toContain("card__bar");
      expect(content.text).toContain("BRAND_INJECT");
      // The vite build must have inlined the bridge script — a bare <script src>
      // would be unloadable from a resources/read HTML string.
      expect(content.text).not.toContain('src="./threat-card.ts"');
    });

    it("serves neutral defaults with no vendor identity", () => {
      const { text } = readResource(THREAT_CARD_RESOURCE_URI);
      expect(text).not.toMatch(/WYRE/i);
      expect(text).not.toContain("00c9db"); // WYRE cyan
      expect(text).not.toContain("ede947"); // WYRE yellow
      expect(text).not.toContain("fonts.googleapis.com"); // no external fetches
    });

    it("injects MCP_BRAND_* env vars into the served HTML", () => {
      vi.stubEnv("MCP_BRAND_NAME", "Acme MSP");
      vi.stubEnv("MCP_BRAND_PRIMARY_COLOR", "#ff0000");
      try {
        const { text } = readResource(THREAT_CARD_RESOURCE_URI);
        expect(text).toContain(
          '<script>window.__BRAND__={"name":"Acme MSP","primaryColor":"#ff0000"}</script>'
        );
        expect(text).not.toContain("BRAND_INJECT");
      } finally {
        vi.unstubAllEnvs();
      }
    });

    it("rejects unknown resource URIs", () => {
      expect(() => readResource("ui://proofpoint/nope.html")).toThrow(/Unknown resource/);
    });
  });

  describe("applyBrandInjection", () => {
    const html = THREAT_CARD_HTML;

    it("replaces the marker with an inline window.__BRAND__ script", () => {
      const out = applyBrandInjection(html, { name: "Acme", primaryColor: "#123456" });
      expect(out).toContain('window.__BRAND__={"name":"Acme","primaryColor":"#123456"}');
      expect(out).not.toContain("BRAND_INJECT");
    });

    it("escapes < so brand values cannot break out of the script tag", () => {
      const out = applyBrandInjection(html, { name: "</script><script>alert(1)" });
      expect(out).not.toContain("</script><script>alert(1)");
      expect(out).toContain("\\u003c/script>\\u003cscript>alert(1)");
    });

    it("returns the HTML unchanged for an empty brand", () => {
      expect(applyBrandInjection(html, {})).toBe(html);
      expect(applyBrandInjection(html, { name: "" })).toBe(html);
    });
  });

  describe("buildThreatCard", () => {
    const threat = {
      id: "b31a3b45cf12a4e8",
      identifiedAt: "2026-07-01T12:00:00.000Z",
      name: "hxxps://malicious.example.com/invoice.pdf",
      type: "url",
      category: "phish",
      detectionType: "inbound",
      severityScore: 90,
      status: "active",
      actors: [{ id: "a1", name: "TA542" }],
      families: [{ id: "f1", name: "Emotet" }],
      campaigns: [{ id: "c1", name: "Q3 invoice lures" }],
    };

    it("normalizes a TAP threat summary into the card payload", () => {
      expect(buildThreatCard(threat)).toEqual({
        id: "b31a3b45cf12a4e8",
        name: "hxxps://malicious.example.com/invoice.pdf",
        type: "url",
        category: "phish",
        status: "active",
        severityScore: 90,
        identifiedAt: "2026-07-01T12:00:00.000Z",
        detectionType: "inbound",
        actors: "TA542",
        families: "Emotet",
        campaigns: "Q3 invoice lures",
      });
    });

    it("falls back to the threat id when the API omits a name", () => {
      const card = buildThreatCard({ id: "abc123" });
      expect(card).toEqual({ id: "abc123", name: "abc123" });
    });

    it("truncates very long threat names so the card payload stays small", () => {
      const card = buildThreatCard({ id: "x", name: "a".repeat(500) });
      expect(card?.name).toHaveLength(300);
    });

    it("reads campaignMembers when campaigns is absent and skips unnamed entries", () => {
      const card = buildThreatCard({
        id: "x",
        campaignMembers: [{ id: "c1" }, { id: "c2", name: "Named" }, null],
        actors: [{ id: "a1" }],
      });
      expect(card?.campaigns).toBe("Named");
      expect(card?.actors).toBeUndefined();
    });

    it("caps entity lists at five names", () => {
      const actors = Array.from({ length: 8 }, (_, i) => ({ id: `${i}`, name: `TA${i}` }));
      const card = buildThreatCard({ id: "x", actors });
      expect(card?.actors).toBe("TA0, TA1, TA2, TA3, TA4");
    });

    it("returns null for payloads that are not a threat summary (best-effort)", () => {
      expect(buildThreatCard(null)).toBeNull();
      expect(buildThreatCard("An unexpected error occurred")).toBeNull();
      expect(buildThreatCard([])).toBeNull();
      expect(buildThreatCard({})).toBeNull();
      expect(buildThreatCard({ id: 42 })).toBeNull(); // TAP threat ids are strings
    });
  });
});
