import unittest

from scanner import scan_source


class ScannerTests(unittest.TestCase):
    def test_tx_origin_has_traceable_line(self):
        findings = scan_source("pragma solidity ^0.8.0;\ncontract A {\nfunction f() public { require(tx.origin == msg.sender); }\n}")
        match = next(item for item in findings if item["rule_id"] == "tx-origin")
        self.assertEqual(match["line"], 3)
        self.assertIn("tx.origin", match["evidence"])
        self.assertEqual(match["severity"], "high")

    def test_dangerous_primitives_are_review_leads(self):
        source = "contract A { function f(address x) public { selfdestruct(payable(x)); x.delegatecall(\"\"); x.call(\"\"); } }"
        ids = {item["rule_id"] for item in scan_source(source)}
        self.assertTrue({"selfdestruct", "delegatecall", "low-level-call"} <= ids)

    def test_comments_and_strings_do_not_trigger(self):
        source = '// tx.origin\n/* selfdestruct(x); */\nstring memory s = "delegatecall .call(";'
        self.assertEqual(scan_source(source), [])

    def test_empty_and_oversize_source_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            scan_source("   ")
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            scan_source("a" * (256 * 1024 + 1))

    def test_evidence_is_bounded(self):
        source = " " * 200 + "contract A { " + "x" * 300 + " tx.origin; }"
        finding = next(item for item in scan_source(source) if item["rule_id"] == "tx-origin")
        self.assertLessEqual(len(finding["evidence"]), 180)
        self.assertIn("tx.origin", finding["evidence"])

    def test_unpaired_unicode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unicode"):
            scan_source("contract A {}\ud800")

    def test_all_findings_are_retained(self):
        source = "tx.origin;\n" * 101 + 'x.delegatecall("");\n'
        findings = scan_source(source)
        self.assertEqual(len(findings), 102)
        self.assertTrue(any(item["rule_id"] == "delegatecall" for item in findings))


if __name__ == "__main__":
    unittest.main()
