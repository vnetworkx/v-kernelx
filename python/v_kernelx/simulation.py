from .engine import VectorKernel, find_valid_nonce


def run_demo():
    kernel = VectorKernel()
    nonce_a = find_valid_nonce("seed-a", 1)
    nonce_b = find_valid_nonce("seed-b", 1)
    if nonce_a is None or nonce_b is None:
        raise RuntimeError("could not find proof-compliant nonce")
    kernel.create_origin("v-a", "pk-a", "space-1", [1000, 2000], "seed-a", nonce_a, 1)
    kernel.create_origin("v-b", "pk-b", "space-1", [50, 75], "seed-b", nonce_b, 1)
    kernel.transfer("v-a", "v-b", [250, 250])
    kernel.drain("v-a", 100)
    kernel.project("v-b", [10, 10], "escrow-1")
    kernel.reconstruct("v-b", [2, 1], [0, 0], "settled")
    return {
        "vectors": [v.to_json() for v in kernel.query_vectors()],
        "records": len(kernel.query_records()),
    }
