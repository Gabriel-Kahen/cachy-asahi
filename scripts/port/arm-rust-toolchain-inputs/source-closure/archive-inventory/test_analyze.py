import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("source_inventory_analysis", HERE / "analyze.py")
ANALYZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZE)


def fixtures(checksum):
    rust = {"status": "COMPLETE_BOUNDED_SCAN", "authenticated_source_pin_verified": True,
            "selected_metadata": [{"path": "Cargo.lock", "declarations": {"packages": [
                {"name": "crate", "version": "1", "source": "registry+https://example.invalid", "checksum": checksum}]}}],
            "vendor_components": {"crate-1": {"licenses": [],
                "Cargo.toml": {"declarations": {"package": {"name": "crate", "version": "1"}}},
                ".cargo-checksum.json": {"declarations": {"package_checksum": "a" * 64, "declared_file_checksums": 2}}}}}
    llvm = {"status": "COMPLETE_BOUNDED_SCAN", "authenticated_source_pin_verified": True, "selected_metadata": []}
    parent = {"materials": {name: {"sha256": "b" * 64, "bytes": 1} for name in ANALYZE.LICENSES.values()}}
    return {"rust": rust, "llvm": llvm}, parent


class DeclarationControls(unittest.TestCase):
    def test_match_requires_checksum_not_only_name_version(self):
        for checksum, matched in (("a" * 64, 1), ("b" * 64, 0), (None, 0)):
            with self.subTest(checksum=checksum):
                reports, parent = fixtures(checksum)
                result = ANALYZE.analyze(reports, parent)
                self.assertEqual(result["cargo_lock_comparisons"][0]["registry_metadata_matches"], matched)
                self.assertEqual(result["offline_build_acceptance"], "HELD")

    def test_partial_scan_and_missing_notice_do_not_become_complete(self):
        reports, parent = fixtures("a" * 64)
        reports["llvm"]["status"] = "PARTIAL"
        result = ANALYZE.analyze(reports, parent)
        self.assertFalse(result["source_reports_complete"])
        self.assertFalse(any(item["metadata_pin_matches_retained_notice"] for item in result["original_notice_comparisons"]))
        self.assertEqual(len(result["vendor_components_without_license_named_files"]), 1)
        self.assertEqual(result["license_completeness_or_legal_acceptance"], "HELD")


if __name__ == "__main__":
    unittest.main()
