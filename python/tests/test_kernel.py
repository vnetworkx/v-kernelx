import unittest

from v_kernelx.engine import VectorKernel, find_valid_nonce
from v_kernelx.model import VectorStateV1, VectorType


class KernelSmokeTests(unittest.TestCase):
    def test_end_to_end_flow(self):
        kernel = VectorKernel()
        nonce_a = find_valid_nonce("seed-a", 1)
        nonce_b = find_valid_nonce("seed-b", 1)
        self.assertIsNotNone(nonce_a)
        self.assertIsNotNone(nonce_b)

        kernel.create_origin("v-a", "pk-a", "space-1", [1000, 2000], "seed-a", int(nonce_a), 1)
        kernel.create_origin("v-b", "pk-b", "space-1", [50, 75], "seed-b", int(nonce_b), 1)
        kernel.transfer("v-a", "v-b", [250, 250])
        kernel.drain("v-a", 100)
        kernel.project("v-b", [10, 10], "escrow-1")
        kernel.reconstruct("v-b", [2, 1], [0, 0], "settled")

        vectors = kernel.query_vectors()
        records = kernel.query_records()
        self.assertEqual(len(vectors), 2)
        self.assertGreaterEqual(len(records), 5)
        self.assertTrue(any(v.vector_id == "v-a" for v in vectors))
        self.assertTrue(any(v.vector_id == "v-b" for v in vectors))
        self.assertTrue(all(len(v.components) == 2 for v in vectors))

    def test_zero_vector_normalization_guard(self):
        state = VectorStateV1.new("zero", "pk", "space-1", [0, 0], VectorType.STANDARD)
        with self.assertRaises(ValueError):
            state.direction_shares()


if __name__ == "__main__":
    unittest.main()
