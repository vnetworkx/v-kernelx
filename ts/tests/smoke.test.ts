import test from "node:test";
import assert from "node:assert/strict";
import { VectorKernelX, findValidNonce } from "../src/client.ts";

const buildKernel = () => new VectorKernelX();

test("end-to-end vector flow", () => {
  const kernel = buildKernel();
  const nonceA = findValidNonce("seed-a", 1);
  const nonceB = findValidNonce("seed-b", 1);

  assert.notEqual(nonceA, null);
  assert.notEqual(nonceB, null);

  kernel.originCreate("v-a", "pk-a", "space-1", [1000, 2000], "seed-a", nonceA ?? 0, 1);
  kernel.originCreate("v-b", "pk-b", "space-1", [50, 75], "seed-b", nonceB ?? 0, 1);
  kernel.transfer("v-a", "v-b", [250, 250]);
  kernel.drain("v-a", 100);
  kernel.project("v-b", [10, 10], "escrow-1");
  kernel.reconstruct("v-b", [2, 1], [0, 0], "settled");

  const vectors = kernel.queryVectors();
  const records = kernel.queryRecords();

  assert.equal(vectors.length, 2);
  assert.ok(records.length >= 5);
  assert.ok(vectors.some((v) => v.vectorId === "v-a"));
  assert.ok(vectors.some((v) => v.vectorId === "v-b"));
  assert.ok(vectors.every((v) => v.components.length === 2));
});

test("zero vector normalization is rejected", () => {
  const kernel = buildKernel();
  const zero = kernel.newVector("zero", "pk", "space-1", [0, 0]);
  assert.throws(() => kernel.directionShares(zero));
});
