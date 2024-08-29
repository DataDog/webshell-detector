# How to contribute

> [!WARNING]
> Do not run any code in code/true-examples-malicious/

## Contents
### Semgrep rules
There are currently 9 Semgrep web shell detection rules. 
They were developed from analyzing these repositories:
- [BlackArch Web Shells](https://github.com/BlackArch/webshells/tree/master/php)
- [Xl7dec Web Shells](https://github.com/xl7dev/WebShell/tree/master/Php)
- [YARA Web Shell Detection Rules](https://github.com/jvoisin/php-malware-finder/blob/master/data/php.yar)
- [Semgrep Security Rules](https://github.com/semgrep/semgrep-rules/tree/develop/php/lang/security)

#### Next steps for semgrep rules (Aug 2024)
- Adding testing
  - Semgrep has a feature to add tests for Semgrep custom rules. In my experience, Semgrep is finicky with small changes so it would be important to add testing for the rules to ensure that they are accurate.
- Increasing web shell detection rate
  - Focus rules around MITRE framework and adding more rules based on the attack vectors
- Severity tags
  - Investigate using Semgrep confidence field instead of indicating severity under metadata

### Scanner
The scanner is for testing the semgrep rules against the test corpus. See the README.md section for how to run the scanner.

#### Next step for the corpus

- Increase true-examples repositories
  - There are often duplicates between web shell github repositories. In order for the scanner tool to output accurate results, there needs to be a deduplication process. Talked with Max: “Implement Fuzzy Hashing: For this you would remove all comments and anything else you don't really care about for comparing uniqueness. The easiest implementation for this would likley be using some existing php minifier to generate the data you will be hashing since it will remove comment by default as well as other thing. For the fuzzy hashing approach, you could use a minifier like this”
- Increase false-examples repositories
- Include less known repositories: code that has worse security measures in place



## :bug: Creating Issues
If you found a bug, search if an issue already exists search if an issue already exists. If it doesn't, you can create a new issue with the bug label. Likewise, if you would like to suggest an enhancement, first see if a similar issue was already created. Then, create a new issue with the enhancement label.

## :white_check_mark: Solving Issues
Create a new branch with the form: <username>/<branch-function>. After changing the repo locally and pushing to your branch's remote origin, create a pull request with a short description of your changes.
