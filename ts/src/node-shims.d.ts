declare module "node:crypto" {
  export function createHash(algorithm: string): {
    update(data: string): any;
    digest(encoding: "hex"): string;
  };
}

declare module "node:test" {
  const test: any;
  export default test;
}

declare module "node:assert/strict" {
  const assert: any;
  export default assert;
}
