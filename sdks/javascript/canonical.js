export function sortJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      if (value[k] !== undefined) {
        out[k] = sortJsonValue(value[k]);
      }
    }
    return out;
  }
  return value;
}

export function canonicalJsonString(value) {
  return JSON.stringify(sortJsonValue(value));
}

export function canonicalJsonBytes(value) {
  return new TextEncoder().encode(canonicalJsonString(value));
}
