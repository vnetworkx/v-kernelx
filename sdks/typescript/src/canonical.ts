export function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(record).sort()) {
      if (record[k] !== undefined) {
        out[k] = sortJsonValue(record[k]);
      }
    }
    return out;
  }
  return value;
}

export function canonicalJsonString(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(value));
}
