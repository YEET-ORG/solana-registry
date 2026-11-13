export type PortfolioReader = "kamino-lending-v1" | "meteora-dlmm-v1" | "canonical-v1";
export type PortfolioConfig = {
  readonly version: 1;
  readonly reader: PortfolioReader;
  readonly enabled: boolean;
  readonly endpoint?: string;
};

function object(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Invalid portfolio config");
  return raw as Record<string, unknown>;
}

function verifiedEndpoint(raw: unknown, domain: string): string {
  if (typeof raw !== "string" || raw.length > 300) throw new Error("Canonical reader endpoint required");
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("Invalid canonical reader endpoint"); }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash ||
      !(url.hostname === domain || url.hostname.endsWith(`.${domain}`))) throw new Error("Canonical reader endpoint must use the verified app domain");
  return url.href;
}

/** Validate registry metadata consumed by fixed, audited readers; it never configures executable code. */
export function validatePortfolioConfig(raw: unknown, id: string, verifiedDomain: string): PortfolioConfig | undefined {
  if (raw === undefined) return undefined;
  const config = object(raw);
  if (Object.keys(config).some((key) => !["version", "reader", "enabled", "endpoint"].includes(key)) ||
      config.version !== 1 || typeof config.enabled !== "boolean" ||
      !["kamino-lending-v1", "meteora-dlmm-v1", "canonical-v1"].includes(String(config.reader))) {
    throw new Error(`Invalid portfolio reader config for ${id}`);
  }
  const reader = config.reader as PortfolioReader;
  if (reader === "kamino-lending-v1" && id !== "kamino") throw new Error("Kamino reader identity mismatch");
  if (reader === "meteora-dlmm-v1" && id !== "meteora") throw new Error("Meteora reader identity mismatch");
  if (reader === "canonical-v1") {
    return { version: 1, reader, enabled: config.enabled, endpoint: verifiedEndpoint(config.endpoint, verifiedDomain.toLowerCase()) };
  }
  if (config.endpoint !== undefined) throw new Error("Built-in readers do not accept endpoint overrides");
  return { version: 1, reader, enabled: config.enabled };
}
