# webshell-detector

> [!WARNING]
> Do not run any code in code/true-examples-malicious/

webshell-detector is a repository that stores static analysis rules for detecting web shells and a test corpus of web shell code. This project utilizes [Semgrep rule writing](https://semgrep.dev/docs/writing-rules/overview) for static analysis and provides a script to scan and analyze the results.
## File Structure
```
.  
├── tests                           # test corpus for detection rules  
│   ├── false-examples              # non-malicious code  
│   └── true-examples               # malicious code, do not run these files directly  
├── rules                           # set of semgrep rules designed for web shell detection  
├── scan.py                         # script to run semgrep scans on the test corpus  
└── README.md
```
## Usage
### Running the Script  
The scanning script scan.py allows you to test the Semgrep rules against different parts of the test corpus and with different sets of rules.


#### Sample usage:
```
# Scan with default settings: all true examples under code/true-examples-malicious, all false examples under code/false-examples/, and all rules under rules/
python scan.py

# Scan a specific path of true examples with all rules
python scan.py --true-examples code/true-examples-malicious/

# Scan a specific path of false examples with all rules
python scan.py --false-examples code/false-examples/

# Scan default true and false examples with 2 specific rules
python scan.py --rules rules/perms.yml --rules rules/obfuscation.yml

# Scan with HIGH tagged rules
# There are 3 options for tagging - LOW, MEDIUM, HIGH. One or multiple are allowed.
python scan.py --tags HIGH

# Scan with default settings and list the FP files
# There are 2 options for listing files - FP, FN. One or multiple are allowed.
python scan.py --list-files FP
```
#### Output
The script will output the number of unique files detected by Semgrep, detection rate, and categorize it based on the true and false code examples.  
Example:
```
+--------------------------+--------+-------+
|                          |  true  | false |
+--------------------------+--------+-------+
| Number of files detected |   78   |   2   |
|      Detection rate      | 38.81% | 0.12% |
+--------------------------+--------+-------+
```
