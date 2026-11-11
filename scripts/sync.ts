/**
 * Solana Registry Synchronization Pipeline
 *
 * Ingests and compiles:
 * 1. DeFiLlama Solana Protocols (real-time TVL, audits, official URLs)
 * 2. Phantom Blocklist & Whitelist (Solana drainers & phishing domains)
 * 3. ScamSniffer Threat Database (Solana-targeted phishing hostnames)
 * 4. Curated Base Solana Apps (Jupiter, Pump.fun, Magic Eden, Tensor, GMGN, etc.)
 *
 * Emits to dist/:
 * - verified-apps.json
 * - blocked-domains.json
 * - registry-metadata.json
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

interface VerifiedAppSocials {
  readonly website?: string;
  readonly twitter?: string;
  readonly discord?: string;
  readonly telegram?: string;
}

interface VerificationSignals {
  readonly officialTwitter?: string;
  readonly dns?: string;
  readonly auditedBy?: readonly string[];
  readonly verifiedDate?: string;
  readonly verifiedBy?: string;
}

interface AppMetricsSourceId {
  readonly defillamaSlug?: string;
}

interface VerifiedApp {
  readonly id: string;
  readonly name: string;
  readonly verifiedDomain: string;
  readonly icon: string;
  readonly category: "DeFi" | "NFTs" | "Trading" | "Memes" | "Tools";
  readonly tags: readonly string[];
  readonly shortDescription: string;
  readonly fullAbout: string;
  readonly socials: VerifiedAppSocials;
  readonly verificationSignals: VerificationSignals;
  readonly metricsSourceId?: AppMetricsSourceId;
  readonly similarAppIds: readonly string[];
}

function extractCanonicalHost(domainOrUrl: string): string {
  const trimmed = domainOrUrl.trim().toLowerCase();
  const withoutScheme = trimmed.replace(/^[a-z]+:\/\//i, "");
  const hostOnly = withoutScheme.split(/[/?#:]/)[0] ?? "";
  return hostOnly.replace(/^www\./i, "");
}

function getRootDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

async function fetchWithTimeout(url: string, timeoutMs = 15000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

async function main() {
  console.log("🚀 Starting Solana Registry Synchronization...");

  const distDir = resolve(process.cwd(), "dist");
  if (!existsSync(distDir)) {
    mkdirSync(distDir, { recursive: true });
  }

  const existingAppsPath = resolve(distDir, "verified-apps.json");
  const existingApps: VerifiedApp[] = existsSync(existingAppsPath)
    ? JSON.parse(readFileSync(existingAppsPath, "utf-8"))
    : [];

  const appMap = new Map<string, VerifiedApp>();
  const rootDomainMap = new Map<string, VerifiedApp>();

  for (const app of existingApps) {
    const host = extractCanonicalHost(app.verifiedDomain);
    appMap.set(host, app);
    if (app.socials?.website) {
      appMap.set(extractCanonicalHost(app.socials.website), app);
    }
    rootDomainMap.set(getRootDomain(host), app);
  }
  console.log(`📦 Loaded ${existingApps.length} base apps`);

  // 1. Fetch & Ingest DeFiLlama Protocols
  console.log("📡 Fetching DeFiLlama protocols...");
  try {
    const res = await fetchWithTimeout("https://api.llama.fi/protocols");
    if (res.ok) {
      const protocols = await res.json();
      const solanaProtocols = protocols.filter(
        (p: any) =>
          p.category !== "CEX" &&
          p.chainTvls &&
          typeof p.chainTvls.Solana === "number" &&
          p.chainTvls.Solana > 200000 &&
          p.url
      );

      console.log(`🔍 Found ${solanaProtocols.length} active Solana protocols on DeFiLlama`);

      let addedFromDefiLlama = 0;
      for (const p of solanaProtocols) {
        const canonicalHost = extractCanonicalHost(p.url);
        if (!canonicalHost || canonicalHost.includes("t.me") || canonicalHost.includes("twitter.com")) {
          continue;
        }

        const rootDomain = getRootDomain(canonicalHost);
        const existing = appMap.get(canonicalHost) || rootDomainMap.get(rootDomain);
        if (existing) {
          if (!existing.metricsSourceId?.defillamaSlug) {
            existing.metricsSourceId = { defillamaSlug: p.slug };
          }
        } else {
          let category: "DeFi" | "Trading" = "DeFi";
          const catLower = (p.category || "").toLowerCase();
          if (catLower.includes("derivative") || catLower.includes("perpetual") || catLower.includes("options")) {
            category = "Trading";
          }

          const id = p.slug.replace(/[^a-z0-9_-]/gi, "").toLowerCase();
          const newApp: VerifiedApp = {
            id,
            name: p.name,
            verifiedDomain: canonicalHost,
            icon: p.logo || `https://${canonicalHost}/favicon.ico`,
            category,
            tags: [p.category || "DeFi", "Solana", "DeFiLlama Verified"].filter(Boolean),
            shortDescription: p.description?.slice(0, 140) || `${p.name} on Solana.`,
            fullAbout: p.description || `${p.name} is a verified protocol on Solana tracked by DeFiLlama.`,
            socials: {
              website: p.url,
              twitter: p.twitter ? `https://x.com/${p.twitter}` : undefined,
            },
            verificationSignals: {
              officialTwitter: p.twitter ? `@${p.twitter}` : undefined,
              dns: `${canonicalHost} (DeFiLlama verified)`,
              auditedBy: p.audits && Number(p.audits) > 0 ? [`${p.audits} Security Audits`] : ["DeFiLlama Tracked"],
              verifiedDate: new Date().toISOString().split("T")[0],
              verifiedBy: "DeFiLlama + GhostWallet",
            },
            metricsSourceId: {
              defillamaSlug: p.slug,
            },
            similarAppIds: ["jupiter", "kamino", "raydium"],
          };
          appMap.set(canonicalHost, newApp);
          rootDomainMap.set(rootDomain, newApp);
          addedFromDefiLlama++;
        }
      }
      console.log(`✅ Integrated ${addedFromDefiLlama} new verified Solana protocols from DeFiLlama`);
    }
  } catch (err) {
    console.warn("⚠️ Failed to fetch DeFiLlama protocols:", err);
  }

  const finalApps = Array.from(new Map(Array.from(appMap.values()).map((a) => [a.id, a])).values());
  console.log(`🌟 Total verified apps compiled: ${finalApps.length}`);

  // 2. Fetch & Ingest Phantom Blocklist + Whitelist
  console.log("🛡️ Fetching Phantom Blocklist & Whitelist...");
  const blockedSet = new Set<string>();
  const whitelistSet = new Set<string>();

  try {
    const whiteRes = await fetchWithTimeout(
      "https://raw.githubusercontent.com/phantom/blocklist/master/whitelist.yaml"
    );
    if (whiteRes.ok) {
      const text = await whiteRes.text();
      for (const line of text.split("\n")) {
        const match = line.match(/^\s*-\s*url:\s*(.+)$/);
        if (match) {
          const raw = match[1].trim().replace(/^["\x27]|["\x27]$/g, "");
          const clean = extractCanonicalHost(raw.replace(/^\*\./, ""));
          if (clean) whitelistSet.add(clean);
        }
      }
      console.log(`📋 Loaded ${whitelistSet.size} Phantom whitelist entries`);
    }

    const blockRes = await fetchWithTimeout(
      "https://raw.githubusercontent.com/phantom/blocklist/master/blocklist.yaml"
    );
    if (blockRes.ok) {
      const text = await blockRes.text();
      for (const line of text.split("\n")) {
        const match = line.match(/^\s*-\s*url:\s*(.+)$/);
        if (match) {
          const raw = match[1].trim().replace(/^["\x27]|["\x27]$/g, "");
          const clean = extractCanonicalHost(raw);
          if (clean && !whitelistSet.has(clean) && !appMap.has(clean)) {
            blockedSet.add(clean);
          }
        }
      }
      console.log(`🚫 Loaded ${blockedSet.size} malicious domains from Phantom`);
    }
  } catch (err) {
    console.warn("⚠️ Failed to fetch Phantom lists:", err);
  }

  // 3. Fetch & Ingest ScamSniffer Solana Threats
  console.log("🚨 Fetching ScamSniffer Threat Database...");
  try {
    const scamRes = await fetchWithTimeout(
      "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"
    );
    if (scamRes.ok) {
      const scamDomains: string[] = await scamRes.json();
      const solanaKeywords = [
        "sol",
        "phantom",
        "solflare",
        "jupiter",
        "jup",
        "raydium",
        "pump",
        "orca",
        "marinade",
        "kamino",
        "drift",
        "tensor",
        "magic",
        "backpack",
        "bonfida",
        "sanctum",
        "meteora",
        "sollet",
        "drainer",
      ];

      let addedFromScamSniffer = 0;
      for (const raw of scamDomains) {
        const clean = extractCanonicalHost(raw);
        if (!clean) continue;
        if (whitelistSet.has(clean) || appMap.has(clean)) continue;

        if (solanaKeywords.some((k) => clean.includes(k))) {
          blockedSet.add(clean);
          addedFromScamSniffer++;
        }
      }
      console.log(`🚫 Added ${addedFromScamSniffer} Solana-related phishing domains from ScamSniffer`);
    }
  } catch (err) {
    console.warn("⚠️ Failed to fetch ScamSniffer database:", err);
  }

  // Explicit fixtures
  blockedSet.add("evil-drainer.xyz");
  blockedSet.add("raydlum.io");
  blockedSet.add("phahtom.commetapiex-ciaim.com");
  blockedSet.add("jupiter-airdrop-claim.cc");
  blockedSet.add("phantom-claim-sol.net");
  blockedSet.add("pumpfun-meme.com");

  const sortedBlockedDomains = Array.from(blockedSet).sort();
  console.log(`🛡️ Total unique blocked domains compiled: ${sortedBlockedDomains.length}`);

  // 4. Write Files
  writeFileSync(existingAppsPath, JSON.stringify(finalApps, null, 2) + "\n", "utf-8");
  console.log(`💾 Saved verified apps to ${existingAppsPath}`);

  const blockedPath = resolve(distDir, "blocked-domains.json");
  writeFileSync(blockedPath, JSON.stringify(sortedBlockedDomains, null, 2) + "\n", "utf-8");
  console.log(`💾 Saved blocked domains to ${blockedPath}`);

  const metadataPath = resolve(distDir, "registry-metadata.json");
  const metadata = {
    version: "2.0.0",
    lastUpdated: new Date().toISOString(),
    verifiedAppCount: finalApps.length,
    blockedDomainCount: sortedBlockedDomains.length,
    sources: [
      "GhostWallet Curated Solana Registry",
      "DeFiLlama Solana Protocol Index",
      "Phantom Open-Source Blocklist (phantom/blocklist)",
      "ScamSniffer Malicious Domain Database (scamsniffer/scam-database)",
    ],
  };
  writeFileSync(metadataPath, JSON.stringify(metadata, null, 2) + "\n", "utf-8");
  console.log(`💾 Saved registry metadata to ${metadataPath}`);

  console.log("✨ Synchronization completed successfully!");
}

main().catch((err) => {
  console.error("❌ Fatal error during sync:", err);
  process.exit(1);
});
