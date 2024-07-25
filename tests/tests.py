import unittest
from unittest.mock import MagicMock, patch
import sys
import json

sys.path.append("..")
from scan import Scanner, CLI

sys.path.remove("..")


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner_true = Scanner("test-data/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)
        self.scanner_false = Scanner("test-data/false-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), False)

    # running scan() to check for correct behavior
    def test_successful_scan_true(self):
        self.scanner_true.scan("rules/", ["test-data/true-examples/1945.php", "test-data/true-examples/c100.php"])

        expected_output_detected = ["test-data/true-examples/1945.php"]
        expected_output_scanned = [
            "test-data/true-examples/1945.php",
            "test-data/true-examples/c100.php",
        ]
        detected_paths = list(set(result["path"] for result in self.scanner_true.total_output["results"]))

        self.assertEqual(detected_paths, expected_output_detected)
        self.assertEqual(self.scanner_true.total_output["paths"]["scanned"], expected_output_scanned)

    # running scan() with faulty inputs to check exception is caught when semgrep fails
    def test_failure_scan_semgrep(self):
        with self.assertRaises(Exception) as context:
            self.scanner_true.scan("rules/", ["tests/test-data/true-examples/1945.php"])
        self.assertTrue("Semgrep failed" in str(context.exception))

    # running scan() with invalid json to check exception is caught when json cannot be decoded
    @patch("subprocess.run")
    def test_failure_scan_json(self, mock_subprocess_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "{invalid_json: true}"
        mock_subprocess_run.return_value = mock_result

        scanner_err = Scanner("test-data/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)

        with self.assertRaises(json.JSONDecodeError):
            scanner_err.scan("rules/", ["test-data/true-examples/1945.php", "test-data/true-examples/c100.php"])

    # running find_files() to check for correct behavior
    def test_successful_find_files(self):
        file_list = self.scanner_false.find_files()

        expected_file_list = [
            "test-data/false-examples/WordPress/wp-activate.php",
            "test-data/false-examples/WordPress/wp-admin/admin.php",
            "test-data/false-examples/WordPress/wp-admin/about.php",
            "test-data/false-examples/WordPress/wp-admin/includes/upgrade.php",
            "test-data/false-examples/mediawiki/rest.php",
            "test-data/false-examples/mediawiki/docs/config-vars.php",
        ]

        self.assertEqual(file_list, expected_file_list)

    # running calculate_results() to check for correct behavior
    def test_successful_calculate_result(self):
        self.scanner_true.scan("rules/", ["test-data/true-examples/1945.php", "test-data/true-examples/c100.php"])
        self.scanner_true.compile_results()
        results = self.scanner_true.calculate_results()
        self.assertEqual(results, [1, 50])

    # running calculate_results() with 0 files scanned to check division by 0 is prevented
    def test_edge_case_calculate_results_zero(self):
        scanner_zero = Scanner("test-data/true-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), True)
        scanner_zero.files_scanned = {}
        results_rate = scanner_zero.calculate_results()[1]
        self.assertEqual(results_rate, 0)

    # running list_files() to check for correct behavior
    def test_successful_list_files(self):
        self.scanner_true.run()
        list_files = self.scanner_true.list_files()
        expected_list_files = "False Negatives:", ["test-data/true-examples/c100.php"]
        self.assertEqual(list_files, expected_list_files)


class TestCLI(unittest.TestCase):

    # running run() with invalid tags to check exception is caught when user inputs invalid tags
    def test_failure_run_invalid_tags(self):
        cli_err = CLI("test-data/true-examples/", "test-data/false-examples/", ("rules/",), ("INVALID"), ("FP"))
        with self.assertRaises(Exception) as context:
            cli_err.run()
        self.assertTrue("Invalid tags" in str(context.exception))

    # running run() with true-examples to check for correct behavior
    def test_successful_run_true_examples(self):
        cli_true = CLI("test-data/true-examples/", "", ("rules/",), ("HIGH", "MEDIUM", "LOW"), None)
        cli_true.run()
        results = cli_true.results
        expected_results = {"true": [1, 50.0]}
        self.assertEqual(results, expected_results)

    # running run() with false-examples to check for correct behavior
    def test_successful_run_false_examples(self):
        cli_false = CLI("", "test-data/false-examples/", ("rules/",), ("HIGH", "MEDIUM", "LOW"), None)
        cli_false.run()
        results = cli_false.results
        expected_results = {"false": [1, 16.666666666666664]}
        self.assertEqual(results, expected_results)

if __name__ == "__main__":
    unittest.main()
