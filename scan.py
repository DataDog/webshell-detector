import subprocess
import json
import sys
import os
from prettytable import PrettyTable

def run_semgrep(target_dir, rules_file, options):
    result = subprocess.run(
        ['semgrep', 'scan', '--config', rules_file, '--json', target_dir],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Semgrep failed with return code {result.returncode}")
        print(result.stderr)
        return
    
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON output: {e}")
        return
    
    files = {result['path'] for result in output['results']}
    
    columns = ['', 'True', 'False']
    myTable = PrettyTable()
    myTable.add_column(columns[0], ['Number of files detected', 'Detection rate'])

    if options[0] == 0 or options[0] == 1:
        true_files_detected = {path for path in files if path.startswith('code/true-examples-malicious/')}
        true_total = len(os.listdir('code/true-examples-malicious/'))
        true_rate = len(true_files_detected)/true_total * 100
        myTable.add_column(columns[1], [len(true_files_detected), str(true_rate) + '%'])

    if options[0] == 0 or options[0] == 2:
        false_files_detected = {path for path in files if path.startswith('code/false-examples/')}
        false_total = len(os.listdir('code/false-examples/'))
        false_positives = len(false_files_detected)/false_total
        false_rate = (1 - false_positives) * 100
        myTable.add_column(columns[2], [len(false_files_detected), str(false_rate) + '%'])
        print('False positive rate:' + str(false_positives*100) + '%')

    print(myTable)

def usage():
    print("Usage: python scan.py <true/false/all> <specific-rule/all>")
    sys.exit(1)

def main():

    target_dir = 'code/'
    rules_file = 'rules/'
    options = [0, 0]

    if len(sys.argv) == 3:
        if sys.argv[1] == 'true':
            target_dir += 'true-examples-malicious'
            options[0] += 1
        elif sys.argv[1] == 'false':
            target_dir += 'false-examples'
            options[0] += 2 
        elif sys.argv[1] != 'all':
            usage()
        
        if os.path.exists(rules_file + sys.argv[2]):
            rules_file += sys.argv[2]
            options[1] += 1
        elif sys.argv[2] != 'all':
            usage()
    elif len(sys.argv) != 1:
        usage()

    run_semgrep(target_dir, rules_file, options)

if __name__ == '__main__':
    main()