import unittest
from vectorspace.parser import parse
from vectorspace.ast import VectorDecl, WalletDecl, CertifyStmt, TransferStmt

class ParserTests(unittest.TestCase):
    def test_basic_program(self):
        program = parse(
            '''
            vector treasury: free = (100, 25, 0);
            wallet owner = bind(pk_treasury);
            certify treasury with ctx(space="global", op="transfer");
            transfer treasury to reserve amount 10 drain 1;
            '''
        )
        self.assertEqual(len(program.statements), 4)
        self.assertIsInstance(program.statements[0], VectorDecl)
        self.assertIsInstance(program.statements[1], WalletDecl)
        self.assertIsInstance(program.statements[2], CertifyStmt)
        self.assertIsInstance(program.statements[3], TransferStmt)

if __name__ == "__main__":
    unittest.main()
