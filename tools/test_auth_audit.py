"""The source-backed authentication check runs, and rejects insecure mutants."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).with_name("auth-audit.py")
spec = importlib.util.spec_from_file_location("audit", PATH)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ComparatorAudit(unittest.TestCase):
    # HMAC comparison is the fixture's actual loaded token function. Replacing it
    # by ordinary equality preserves auth results but must fail the timing contract.
    def test_python_comparator_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.py"
            path.write_text("import hmac\ndef token_matches(expected, actual):\n    return hmac.compare_digest(expected, actual)\n")
            self.assertTrue(audit.python_comparator(path))
            path.write_text("def token_matches(expected, actual):\n    return expected == actual\n")
            self.assertFalse(audit.python_comparator(path))

    # Both fixed-size hashing and ConstantTimeEq must remain wired to admission;
    # a byte equality replacement must not be accepted by the executable audit.
    def test_rust_comparator_mutation(self):
        source = '''use subtle::ConstantTimeEq;
let valid = |token: &str| bool::from(token_hash.ct_eq(&Sha256::digest(token.as_bytes())));
.filter(|(scheme, token)| scheme.eq_ignore_ascii_case("Bearer") && valid(token))'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.rs"
            path.write_text(source)
            self.assertTrue(audit.rust_comparator(path))
            path.write_text(source.replace("token_hash.ct_eq(&Sha256::digest(token.as_bytes()))", "token_hash == Sha256::digest(token.as_bytes())"))
            self.assertFalse(audit.rust_comparator(path))


if __name__ == "__main__":
    unittest.main()
