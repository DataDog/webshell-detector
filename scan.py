from typing import List, Optional, Tuple, Dict
import click
import subprocess
import json
import sys
import os
from prettytable import PrettyTable

def run_semgrep(target_dir: str, rules: Tuple[str, ...]) -> Optional[List[int]]:

    total_output = {
        "results": [],
        "errors": [],
        "paths": {"scanned": []}
    }

    target_dir += '*/**'
    for rule in rules:
        command = 'semgrep scan --config ' + rule + ' --json ' + target_dir
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True
        )

        if result.returncode != 0:
            print(f"Semgrep failed with return code {result.returncode} with command semgrep scan --config {rule} --json {target_dir}\n{result.stderr}")
            sys.exit(1)

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON output: {e}")
            sys.exit(1)
        
        total_output['results'].extend(output.get('results', []))
        total_output['errors'].extend(output.get('errors', []))
        total_output['paths']['scanned'].extend(output.get('paths', {}).get('scanned', []))

    files_detected = len({result['path'] for result in total_output['results']})
    files_scanned = len(set(total_output['paths']['scanned']))
    rate = files_detected/files_scanned * 100
    
    return [files_detected, rate]

def generate_table(results: Dict[str, List[int]]):
    output_table = PrettyTable()
    output_table.add_column('', ['Number of files detected', 'Detection rate'])

    for key in results:
        results[key][1] = str(round(results[key][1], 2)) + '%'
        output_table.add_column(key, results[key])

    return output_table

@click.command()
@click.option('--true-examples', type=click.Path(exists=True), default=None, help='path to true examples')
@click.option('--false-examples', type=click.Path(exists=True), default=None, help='path to false examples')
@click.option('--rules', multiple=True, type=click.Path(exists=True), default=None, help='path to rules')
def main(true_examples: str, false_examples: str, rules: Tuple[str, ...]) -> None:
    
    if not true_examples and not false_examples:
        true_examples = 'code/true-examples-malicious/'
        false_examples = 'code/false-examples/'
    if not rules:
        rules = ['rules/']

    results = {}
    if true_examples:
        true_result = run_semgrep(true_examples, rules)
        results['true'] = true_result
    if false_examples:
        false_result = run_semgrep(false_examples, rules)
        results['false'] = false_result

    output_table = generate_table(results)
    print(output_table)

if __name__ == '__main__':
    main()