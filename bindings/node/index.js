import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function resolveNativeLibraryPath() {
  const candidates = [
    resolve(here, "../../target/release/libvnetwork_node_binding.so"),
    resolve(here, "../../target/debug/libvnetwork_node_binding.so"),
    resolve(here, "../../target/release/libvnetwork_node_binding.dylib"),
    resolve(here, "../../target/debug/libvnetwork_node_binding.dylib"),
  ];
  return candidates.find((p) => existsSync(p)) ?? null;
}

export function hasNativeLibrary() {
  return resolveNativeLibraryPath() !== null;
}
