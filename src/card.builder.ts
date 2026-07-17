/**
 * Threat-card payload builder for the MCP Apps (SEP-1865) UI surface.
 *
 * proofpoint_threat_get_by_id results get a normalized `_card` object
 * attached (see domains/threat-intel.ts) that the ui:// threat card renders
 * from. The card is progressive enhancement: every step here is best-effort,
 * and a null return simply means the host renders no card while the JSON
 * payload is unchanged.
 *
 * The card is READ-ONLY: Proofpoint TAP threat intelligence has no safe,
 * non-destructive write action to surface, so the card never calls back.
 */

export const THREAT_CARD_RESOURCE_URI = "ui://proofpoint/threat-card.html";

/** MCP Apps resource MIME (RESOURCE_MIME_TYPE in @modelcontextprotocol/ext-apps). */
export const MCP_APP_RESOURCE_MIME = "text/html;profile=mcp-app";

/**
 * Tool `_meta` advertising the card. Carries both the canonical flat key
 * (RESOURCE_URI_META_KEY in ext-apps) and the nested form ext-apps'
 * registerAppTool emits, so any MCP Apps host revision finds it.
 */
export const THREAT_CARD_META = {
  "ui/resourceUri": THREAT_CARD_RESOURCE_URI,
  ui: { resourceUri: THREAT_CARD_RESOURCE_URI },
} as const;

/** Mirror of Brand in ui/threat-card.ts — keep in sync. */
export interface CardBrand {
  name?: string;
  logoUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  bg?: string;
  text?: string;
}

/** The BRAND_INJECT comment marker baked into the card HTML (see ui/index.html). */
const BRAND_INJECT_RE = /<!--\s*BRAND_INJECT:[\s\S]*?-->/;

/**
 * Serve-time brand injection: replace the BRAND_INJECT marker with an inline
 * `window.__BRAND__` script so self-hosters can theme the card without
 * rebuilding the bundle. An empty brand returns the HTML unchanged (the card
 * renders its neutral defaults). `<` is escaped so brand values can never
 * break out of the script tag.
 */
export function applyBrandInjection(html: string, brand: CardBrand): string {
  if (!brand || Object.values(brand).every((v) => !v)) return html;
  const json = JSON.stringify(brand).replace(/</g, "\\u003c");
  return html.replace(BRAND_INJECT_RE, `<script>window.__BRAND__=${json}</script>`);
}

/**
 * Resolve brand overrides from MCP_BRAND_* environment variables. Guarded for
 * runtimes without `process`, where this returns an empty brand and the card
 * serves its neutral defaults.
 */
export function resolveBrandFromEnv(): CardBrand {
  if (typeof process === "undefined" || !process.env) return {};
  const env = process.env;
  const brand: CardBrand = {};
  if (env.MCP_BRAND_NAME) brand.name = env.MCP_BRAND_NAME;
  if (env.MCP_BRAND_LOGO_URL) brand.logoUrl = env.MCP_BRAND_LOGO_URL;
  if (env.MCP_BRAND_PRIMARY_COLOR) brand.primaryColor = env.MCP_BRAND_PRIMARY_COLOR;
  if (env.MCP_BRAND_ACCENT_COLOR) brand.accentColor = env.MCP_BRAND_ACCENT_COLOR;
  if (env.MCP_BRAND_BG) brand.bg = env.MCP_BRAND_BG;
  if (env.MCP_BRAND_TEXT) brand.text = env.MCP_BRAND_TEXT;
  return brand;
}

/** Mirror of ThreatCard in ui/threat-card.ts — keep in sync. */
export interface ThreatCard {
  id: string;
  name: string;
  type?: string;
  category?: string;
  status?: string;
  severityScore?: number;
  identifiedAt?: string;
  detectionType?: string;
  actors?: string;
  families?: string;
  campaigns?: string;
}

const CARD_NAME_MAX_LENGTH = 300;
const CARD_LIST_LIMIT = 5;

/**
 * Join the `name` fields of a TAP entity list ([{id, name}, …]) into a
 * display string. The TAP Threat API resolves names server-side already,
 * so no extra lookups are needed; entries without a name are skipped.
 */
function joinNames(value: unknown): string | undefined {
  if (!Array.isArray(value)) return undefined;
  const names = value
    .map((entry) =>
      entry && typeof entry === "object" && typeof (entry as { name?: unknown }).name === "string"
        ? ((entry as { name: string }).name)
        : undefined
    )
    .filter((name): name is string => !!name)
    .slice(0, CARD_LIST_LIMIT);
  return names.length > 0 ? names.join(", ") : undefined;
}

/**
 * Build the renderable card from a proofpoint_threat_get_by_id payload
 * (TAP Threat API /v2/threat/summary/{threatId}). Returns null when the
 * payload doesn't look like a threat summary — the tool result is then
 * served without a card.
 */
export function buildThreatCard(threat: unknown): ThreatCard | null {
  if (!threat || typeof threat !== "object" || Array.isArray(threat)) return null;
  const t = threat as Record<string, unknown>;

  if (typeof t.id !== "string" || !t.id) return null;

  const card: ThreatCard = {
    id: t.id,
    // The threat "name" is the malicious URL / attachment hash / subject —
    // untrusted vendor text the UI only ever places in DOM text nodes.
    name:
      typeof t.name === "string" && t.name
        ? t.name.slice(0, CARD_NAME_MAX_LENGTH)
        : t.id,
  };

  if (typeof t.type === "string" && t.type) card.type = t.type;
  if (typeof t.category === "string" && t.category) card.category = t.category;
  if (typeof t.status === "string" && t.status) card.status = t.status;
  if (typeof t.severityScore === "number" && Number.isFinite(t.severityScore)) {
    card.severityScore = t.severityScore;
  }
  if (typeof t.identifiedAt === "string" && t.identifiedAt) {
    card.identifiedAt = t.identifiedAt;
  }
  if (typeof t.detectionType === "string" && t.detectionType) {
    card.detectionType = t.detectionType;
  }

  const actors = joinNames(t.actors);
  const families = joinNames(t.families);
  const campaigns = joinNames(t.campaigns ?? t.campaignMembers);
  if (actors) card.actors = actors;
  if (families) card.families = families;
  if (campaigns) card.campaigns = campaigns;

  return card;
}
