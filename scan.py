import click
import subprocess
import json
import sys
import os
import shlex
import glob
from typing import List, Tuple, Dict
from itertools import batched
from prettytable import PrettyTable


class Scanner:
    def __init__(self, target_dir: str, rules: Tuple[str, ...], tags: Tuple[str, ...], examples: bool) -> None:
        self.target_dir = target_dir
        self.rules = rules
        self.tags = tags
        self.examples = examples
        self.total_output = {"results": [], "errors": [], "paths": {"scanned": []}}
        self.batch_size = 5000
        self.files_detected = set()
        self.files_scanned = set()

    def run(self) -> List[int]:
        files = self.find_files()
        for batch in batched(files, self.batch_size):
            for rule in self.rules:
                self.scan(rule, batch)
        self.compile_results()
        return self.calculate_results()

    def scan(self, rule: str, batch: List[str]) -> None:

        if not batch:
            return

        batch_str = " ".join(shlex.quote(file) for file in batch)
        command = f"semgrep scan --config {rule} --json {batch_str}"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(f"Semgrep failed with return code {result.returncode} with command semgrep scan --config {rule} --json {self.target_dir}\n{result.stderr}")

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON output: {e}")
            sys.exit(1)

        filtered_results = self.filter_results(output.get("results", []))
        self.total_output["results"].extend(filtered_results)
        self.total_output["errors"].extend(output.get("errors", []))
        self.total_output["paths"]["scanned"].extend(output.get("paths", {}).get("scanned", []))

    def filter_results(self, results: List[Dict]) -> List[Dict]:
        filtered_results = []
        for result in results:
            if "tags" in result.get("extra", {}).get("metadata", {}):
                tags = result["extra"]["metadata"]["tags"]
                if any(tag in tags for tag in self.tags):
                    filtered_results.append(result)
        return filtered_results

    def find_files(self) -> List[str]:
        pattern = os.path.join(self.target_dir, "**", "*.php")
        file_list = glob.glob(pattern, recursive=True)
        return file_list

    def compile_results(self) -> None:
        self.files_detected = set(result["path"] for result in self.total_output["results"])
        self.files_scanned = set(self.total_output["paths"]["scanned"])

    def calculate_results(self) -> List[int]:
        files_detected = len(self.files_detected)
        files_scanned = len(self.files_scanned)
        if files_scanned:
            rate = files_detected / files_scanned * 100
        else:
            rate = 0
            print(f"No files scanned in {self.target_dir}")
        return [files_detected, rate]

    def list_files(self) -> Tuple[str, List[os.PathLike]]:
        if self.examples:
            return "False Negatives:", [path for path in self.files_scanned if path not in self.files_detected]
        else:
            return "False Positives:", [path for path in self.files_detected]


class CLI:
    def __init__(self, true_examples: str, false_examples: str, rules: Tuple[str, ...], tags: Tuple[str, ...], list_files: Tuple[str, ...]) -> None:
        self.true_examples = true_examples
        self.false_examples = false_examples

        # Run on default test set when neither true or false examples are inputted
        if not self.true_examples and not self.false_examples:
            self.true_examples = "tests/true-examples/"
            self.false_examples = "tests/false-examples/"

        self.rules = rules
        self.tags = tags
        self.list_files = list_files
        self.results = {}

    def run(self) -> None:
        if not any(tag in ("HIGH", "MEDIUM", "LOW") for tag in self.tags): # No valid tags, stop scanning
            print("Invalid tags. Make sure you are scanning with LOW/MEDIUM/HIGH tags.")
            sys.exit(1)
        elif any(tag not in ("HIGH", "MEDIUM", "LOW") for tag in self.tags): # Some valid and some invalid tags, continue scanning on valid tags
            print("There are some invalid tags. Make sure you are scanning only with LOW/MEDIUM/HIGH tags. Scanning will continue with valid tags.")
        
        if self.true_examples:
            scanner_true = Scanner(self.true_examples, self.rules, self.tags, examples=True)
            self.results["true"] = scanner_true.run()
        if self.false_examples:
            scanner_false = Scanner(self.false_examples, self.rules, self.tags, examples=False)
            self.results["false"] = scanner_false.run()
        output_table = self.generate_table(self.results)
        print(output_table)

        if self.list_files:
            if self.true_examples and "FN" in self.list_files:  # scanning on true examples, show false negatives
                msg, files = scanner_true.list_files()
            elif self.false_examples and "FP" in self.list_files:  # scanning on false examples, show false positives
                msg, files = scanner_false.list_files()
            else:
                msg, files = "No FN or FP for the scan options provided. Make sure you are scanning the correct examples for FN or FP checks.", []
            self.print_files(msg, files)

    def print_files(self, msg: str, files: List[str]) -> None:
        print(msg)
        print(*files, sep="\n")

    def generate_table(self, results: Dict[str, List[int]]) -> PrettyTable:
        output_table = PrettyTable()

        output_table.add_column("", ["Number of files detected", "Detection rate"])
        [output_table.add_column(key, [results[key][0], f"{round(results[key][1], 2)}%"]) for key in results]

        return output_table


@click.command()
@click.option("--true-examples", type=click.Path(exists=True), help="path to true examples")
@click.option("--false-examples", type=click.Path(exists=True), help="path to false examples")
@click.option("--rule", multiple=True, type=click.Path(exists=True), default=("rules/",), help="path to rules")
@click.option("--tag", multiple=True, default=["LOW", "MEDIUM", "HIGH"], help="tag options LOW/MEDIUM/HIGH")
@click.option("--list-files", multiple=True, help="list file options FN/FP")
def main(
    true_examples: str, false_examples: str, rules: Tuple[str, ...], tags: Tuple[str, ...], list_files: Tuple[str, ...]) -> None:
    cli = CLI(true_examples, false_examples, rules, tags, list_files)
    cli.run()


if __name__ == "__main__":
    main()
