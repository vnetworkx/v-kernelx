import unittest
from vectorspace.runtime import Runtime

class RuntimeTests(unittest.TestCase):
    def test_execute(self):
        runtime = Runtime()
        report = runtime.execute_source(
            '''
            vector treasury: free = (100, 25, 0);
            wallet owner = bind(pk_treasury);
            certify treasury with ctx(space="global", op="transfer");
            query treasury.certification;
            '''
        )
        self.assertTrue(report["outputs"])
        self.assertIn("treasury", report["vectors"])

if __name__ == "__main__":
    unittest.main()
