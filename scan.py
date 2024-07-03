import click
import subprocess
import json
import sys
import os
from prettytable import PrettyTable

def run_semgrep(target_dir, rules):

    total_output = {}

    # should implement this better
    if target_dir == 'code/false-examples/':
        test = 'code/false-examples/*/**'
    else:
        test = target_dir

    for rule in rules:
        command = 'semgrep scan --config ' + rule + ' --json ' + test
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True
        )

        if result.returncode != 0:
            print(f"Semgrep failed with return code {result.returncode} with command semgrep scan --config {rule} --json {test}\n{result.stderr}")
            sys.exit(1)

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON output: {e}")
            sys.exit(1)
        
        total_output.update(output)

    # might be nice to also print number of files scanned
    # print(total_output['paths']['scanned'])

    files = {result['path'] for result in total_output['results']}
    files_detected = {path for path in files if path.startswith(target_dir)} 
    total = len(os.listdir(target_dir))
    rate = len(files_detected)/total * 100
    return [len(files_detected), rate]

@click.command()
@click.option('--true-examples', type=click.Path(exists=True), default=None, help='path to true examples')
@click.option('--false-examples', type=click.Path(exists=True), default=None, help='path to false examples')
@click.option('--rules', multiple=True, type=click.Path(exists=True), default=None, help='path to rules')
def main(true_examples, false_examples, rules):

    columns = ['', 'True', 'False']
    myTable = PrettyTable()
    myTable.add_column(columns[0], ['Number of files detected', 'Detection rate'])

    if not true_examples and not false_examples:
        true_examples = 'code/true-examples-malicious/'
        false_examples = 'code/false-examples/'
    if not rules:
        rules = ['rules/']

    if true_examples:
        true_result = run_semgrep(true_examples, rules)
        true_result[1] = str(true_result[1]) + '%'
        myTable.add_column(columns[1], true_result)
    if false_examples:
        false_result = run_semgrep(false_examples, rules)
        false_result[1] = str(false_result[1]) + '%'
        myTable.add_column(columns[2], false_result)
        print('False positive rate: ' + false_result[1])
    
    print(myTable)

if __name__ == '__main__':
    main()