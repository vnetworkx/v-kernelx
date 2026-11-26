import "server-only";
export {
  disconnectedStatusDto,
  mapNetworkSnapshotToWorkbenchProps,
  type WorkbenchInitialProps,
} from "./snapshot-mapper";

export function getNetworkApiUrl(): string {
  const configured = process.env.VNETWORK_API_URL?.trim();
  if (!configured || configured === "null" || configured === "undefined") {
    return "http://127.0.0.1:8080";
  }
  return configured.replace(/\/+$/, "");
}

export async function fetchNetworkApiJson<T = Record<string, unknown>>(
  endpointPath: string,
): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
  const endpoint = getNetworkApiUrl();
  try {
    const res = await fetch(`${endpoint}${endpointPath}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(4000),
    });
    const data = (await res.json().catch(() => null)) as T | null;
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        data,
        error:
          (data as Record<string, unknown> | null)?.error?.toString() ??
          `Upstream HTTP ${res.status}`,
      };
    }
    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 503,
      data: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function postNetworkApiJson<T = Record<string, unknown>>(
  endpointPath: string,
  payload: unknown,
): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
  const endpoint = getNetworkApiUrl();
  try {
    const res = await fetch(`${endpoint}${endpointPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    const data = (await res.json().catch(() => null)) as T | null;
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        data,
        error:
          (data as Record<string, unknown> | null)?.error?.toString() ??
          `Upstream HTTP ${res.status}`,
      };
    }
    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 503,
      data: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchNetworkExplorerSnapshot(): Promise<{
  reachable: boolean;
  endpoint: string;
  data: Record<string, unknown> | null;
  error?: string;
}> {
  const endpoint = getNetworkApiUrl();
  const res = await fetchNetworkApiJson<Record<string, unknown>>("/v1/explorer/network");
  return {
    reachable: res.ok,
    endpoint,
    data: res.ok ? res.data : null,
    error: res.error,
  };
}
