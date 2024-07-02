# webshell-detector
webshell-detector is a repository that stores static analysis rules for detecting web shells and a test corpus of web shell code. This project utilizes Semgrep for static analysis and provides a script to scan and analyze the results.
## Features
Static Analysis Rules: A set of Semgrep rules designed to detect web shells.  
Test Corpus: A collection of web shell code and non-malicious web server code for testing the detection rules.  
Scanning Script: A Python script to run Semgrep scans on the test corpus and analyze the results.
## Usage
### Running the Script  
The scanning script scan.py allows you to test the Semgrep rules against different parts of the test corpus and with different sets of rules.

#### Usage:
```
python scan.py <true/false/all> <specific-rule/all>
```
#### Arguments:
* Test Corpus:
    * true: Tests only the true examples of web shell code.
    * false: Tests only the false examples.
    * all: Tests both true and false examples.
* Rules:
    * specific-rule: Tests using a specific Semgrep rule file.
    * all: Tests using all the Semgrep rules in the rules/ directory.

#### Examples:  
Run with default settings (all test corpus and all rules):
```
python scan.py
```
This command defaults to testing all examples in the code/ directory with all rules in the rules/ directory.

Run on true examples with all rules:
```
python scan.py true all
```
Run on false examples with a specific rule:
```
python scan.py false path/to/specific-rule.yml
```
#### Output
The script will output the number of unique files detected by Semgrep and categorize it based on the true and false code examples as well as a false positive percentage.  
Example:
```
False positive rate:0.0%
+--------------------------+--------+--------+
|                          |  True  | False  |
+--------------------------+--------+--------+
| Number of files detected |   3    |   0    |
|      Detection rate      | 100.0% | 100.0% |
+--------------------------+--------+--------+
```
