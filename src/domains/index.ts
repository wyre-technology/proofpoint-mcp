/**
 * Domain handlers index
 *
 * Lazy-loads domain handlers to avoid loading everything upfront.
 */

import type { DomainHandler, DomainName } from "../utils/types.js";
import { getAllDomainNames } from "../utils/types.js";

// Cache for loaded domain handlers
const domainCache = new Map<DomainName, DomainHandler>();

/**
 * Lazy-load a domain handler
 */
export async function getDomainHandler(
  domain: DomainName
): Promise<DomainHandler> {
  const cached = domainCache.get(domain);
  if (cached) {
    return cached;
  }

  let handler: DomainHandler;

  switch (domain) {
    case "tap": {
      const { tapHandler } = await import("./tap.js");
      handler = tapHandler;
      break;
    }
    case "quarantine": {
      const { quarantineHandler } = await import("./quarantine.js");
      handler = quarantineHandler;
      break;
    }
    case "threat_intel": {
      const { threatIntelHandler } = await import("./threat-intel.js");
      handler = threatIntelHandler;
      break;
    }
    case "dlp": {
      const { dlpHandler } = await import("./dlp.js");
      handler = dlpHandler;
      break;
    }
    case "people": {
      const { peopleHandler } = await import("./people.js");
      handler = peopleHandler;
      break;
    }
    case "forensics": {
      const { forensicsHandler } = await import("./forensics.js");
      handler = forensicsHandler;
      break;
    }
    case "smart_search": {
      const { smartSearchHandler } = await import("./smart-search.js");
      handler = smartSearchHandler;
      break;
    }
    case "policy": {
      const { policyHandler } = await import("./policy.js");
      handler = policyHandler;
      break;
    }
    case "url_defense": {
      const { urlDefenseHandler } = await import("./url-defense.js");
      handler = urlDefenseHandler;
      break;
    }
    case "events": {
      const { eventsHandler } = await import("./events.js");
      handler = eventsHandler;
      break;
    }
    case "reports": {
      const { reportsHandler } = await import("./reports.js");
      handler = reportsHandler;
      break;
    }
    default:
      throw new Error(`Unknown domain: ${domain}`);
  }

  domainCache.set(domain, handler);
  return handler;
}

/**
 * Get all available domain names
 */
export function getAvailableDomains(): DomainName[] {
  return getAllDomainNames();
}

/**
 * Clear the domain cache (useful for testing)
 */
export function clearDomainCache(): void {
  domainCache.clear();
}
