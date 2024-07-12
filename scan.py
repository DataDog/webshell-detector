import click
import subprocess
import json
import sys
import os
import shlex
from typing import List, Tuple, Dict
from itertools import batched
from prettytable import PrettyTable


class Scanner:
    def __init__(self, target_dir: str, rules: Tuple[str, ...]) -> None:
        self.target_dir = target_dir
        self.rules = rules
        self.total_output = {"results": [], "errors": [], "paths": {"scanned": []}}
        self.batch_size = 5000

    def run(self) -> List[int]:
        files = self.find_files()
        for batch in batched(files, self.batch_size):
            for rule in self.rules:
                self.scan(rule, batch)
        return self.calculate_results()

    def scan(self, rule: str, batch: List[str]) -> None:

        if not batch:
            return

        batch_str = " ".join(shlex.quote(file) for file in batch)
        command = f'semgrep scan --config {rule} --json {batch_str}'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(
                f"Semgrep failed with return code {result.returncode} with command semgrep scan --config {rule} --json {self.target_dir}\n{result.stderr}"
            )

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON output: {e}")
            sys.exit(1)

        self.total_output["results"].extend(output.get("results", []))
        self.total_output["errors"].extend(output.get("errors", []))
        self.total_output["paths"]["scanned"].extend(output.get("paths", {}).get("scanned", []))

    def find_files(self) -> List[str]:
        file_list = []
        for root, _, files in os.walk(os.path.dirname(self.target_dir)):
            for file in files:
                if file.endswith(".php"):
                    file_list.append(os.path.join(root, file))
        return file_list

    def calculate_results(self) -> List[int]:
        files_detected = len(set(result["path"] for result in self.total_output["results"]))
        files_scanned = len(set(self.total_output["paths"]["scanned"]))
        rate = files_detected / files_scanned * 100 if files_scanned else 0
        return [files_detected, rate]


class CLI:
    def __init__(self, true_examples: str, false_examples: str, rules: Tuple[str, ...]) -> None:
        self.true_examples = true_examples
        self.false_examples = false_examples

        # Run on default test set when neither true or false examples are inputted
        if not self.true_examples and not self.false_examples:
            self.true_examples = "tests/true-examples/"
            self.false_examples = "tests/false-examples/"

        self.rules = rules or ("rules/", )
        self.results = {}

    def run(self) -> None:
        if self.true_examples:
            self.results["true"] = Scanner(self.true_examples, self.rules).run()
        if self.false_examples:
            self.results["false"] = Scanner(self.false_examples, self.rules).run()

        output_table = self.generate_table(self.results)
        print(output_table)

    def generate_table(self, results: Dict[str, List[int]]) -> PrettyTable:
        output_table = PrettyTable()

        output_table.add_column("", ["Number of files detected", "Detection rate"])
        [
            output_table.add_column(key, [results[key][0], f"{round(results[key][1], 2)}%"])
            for key in results
        ]

        return output_table


@click.command()
@click.option("--true-examples", type=click.Path(exists=True), help="path to true examples")
@click.option("--false-examples", type=click.Path(exists=True), help="path to false examples")
@click.option("--rules", multiple=True, type=click.Path(exists=True), default=["rules/"], help="path to rules")
def main(true_examples: str, false_examples: str, rules: Tuple[str, ...]) -> None:
    cli = CLI(true_examples, false_examples, rules)
    cli.run()


if __name__ == "__main__":
    main()
