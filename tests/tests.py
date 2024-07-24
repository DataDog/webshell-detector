import unittest
from unittest.mock import MagicMock, patch
import sys
import json

sys.path.append("..")
from scan import Scanner, CLI

sys.path.remove("..")


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner_true = Scanner("examples/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)
        self.scanner_false = Scanner("examples/false-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), False)

    def test_scan_success(self):
        self.scanner_true.scan("rules/", ["examples/true-examples/1945.php", "examples/true-examples/c100.php"])

        expected_output_detected = ["examples/true-examples/1945.php"]
        expected_output_scanned = [
            "examples/true-examples/1945.php",
            "examples/true-examples/c100.php",
        ]
        detected_paths = list(set(result["path"] for result in self.scanner_true.total_output["results"]))

        self.assertEqual(detected_paths, expected_output_detected)
        self.assertEqual(self.scanner_true.total_output["paths"]["scanned"], expected_output_scanned)

    def test_scan_semgrep_fail(self):
        with self.assertRaises(Exception) as context:
            self.scanner_true.scan("rules/", ["tests/examples/true-examples/1945.php"])
        self.assertTrue("Semgrep failed" in str(context.exception))

    @patch("subprocess.run")
    def test_scan_json_err(self, mock_subprocess_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "{invalid_json: true}"
        mock_subprocess_run.return_value = mock_result

        scanner_err = Scanner("examples/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)

        with self.assertRaises(json.JSONDecodeError):
            scanner_err.scan("tests/rules/", ["tests/examples/true-examples/1945.php", "tests/examples/true-examples/c100.php"])

    def test_find_files(self):
        file_list = self.scanner_false.find_files()

        expected_file_list = [
            "examples/false-examples/WordPress/wp-activate.php",
            "examples/false-examples/WordPress/wp-admin/admin.php",
            "examples/false-examples/WordPress/wp-admin/about.php",
            "examples/false-examples/WordPress/wp-admin/includes/upgrade.php",
            "examples/false-examples/mediawiki/rest.php",
            "examples/false-examples/mediawiki/docs/config-vars.php",
        ]

        self.assertEqual(file_list, expected_file_list)

    def test_calculate_results_success(self):
        self.scanner_true.scan("rules/", ["examples/true-examples/1945.php", "examples/true-examples/c100.php"])
        self.scanner_true.compile_results()
        results = self.scanner_true.calculate_results()
        self.assertEqual(results, [1, 50])

    def test_calculate_results_zero(self):
        scanner_zero = Scanner("examples/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)
        scanner_zero.files_scanned = {}
        results_rate = scanner_zero.calculate_results()[1]
        self.assertEqual(results_rate, 0)

    def test_list_files(self):
        self.scanner_true.run()
        list_files = self.scanner_true.list_files()
        expected_list_files = "False Negatives:", ["examples/true-examples/c100.php"]
        self.assertEqual(list_files, expected_list_files)


class TestCLI(unittest.TestCase):

    def test_run_invalid_tags(self):
        cli_err = CLI("examples/true-examples/", "examples/false-examples/", ("rules/",), ("INVALID"), ("FP"))
        with self.assertRaises(Exception) as context:
            cli_err.run()
        self.assertTrue("Invalid tags" in str(context.exception))

    def test_run_default(self):
        cli_default = CLI("", "", ("rules/",), ("HIGH", "MEDIUM", "LOW"), None)
        cli_default.run()
        results = cli_default.results
        expected_results = {"true": [1, 50.0], "false": [1, 16.666666666666664]}
        self.assertEqual(results, expected_results)

    def test_run_true(self):
        cli_true = CLI("examples/true-examples/", "", ("rules/",), ("HIGH", "MEDIUM", "LOW"), None)
        cli_true.run()
        results = cli_true.results
        expected_results = {"true": [1, 50.0]}
        self.assertEqual(results, expected_results)

    def test_run_false(self):
        cli_false = CLI("", "examples/false-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), None)
        cli_false.run()
        results = cli_false.results
        expected_results = {"false": [1, 16.666666666666664]}
        self.assertEqual(results, expected_results)

if __name__ == "__main__":
    unittest.main()
