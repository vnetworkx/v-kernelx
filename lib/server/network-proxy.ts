import "server-only";

export function getNetworkApiUrl(): string {
  const configured = process.env.VNETWORK_API_URL?.trim();
  if (!configured || configured === "null" || configured === "undefined") {
    return "http://127.0.0.1:8080";
  }
  return configured.replace(/\/+$/, "");
}

export async function fetchNetworkExplorerSnapshot(): Promise<{
  reachable: boolean;
  endpoint: string;
  data: Record<string, unknown> | null;
  error?: string;
}> {
  const endpoint = getNetworkApiUrl();
  try {
    const res = await fetch(`${endpoint}/v1/explorer/network`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) {
      return {
        reachable: false,
        endpoint,
        data: null,
        error: `HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as Record<string, unknown>;
    return { reachable: true, endpoint, data };
  } catch (err) {
    return {
      reachable: false,
      endpoint,
      data: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
