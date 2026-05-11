from .engine import VectorKernel

def run_demo():
    kernel = VectorKernel()
    kernel.create_origin("v-a", "pk-a", "space-1", [1000, 2000], "seed-a", 1, 1)
    kernel.create_origin("v-b", "pk-b", "space-1", [50, 75], "seed-b", 2, 1)
    kernel.transfer("v-a", "v-b", [250, 250])
    kernel.drain("v-a", 100)
    kernel.project("v-b", [10, 10], "escrow-1")
    return {
        "vectors": [v.to_json() for v in kernel.query_vectors()],
        "records": len(kernel.query_records()),
    }
