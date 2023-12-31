# Magic-SigExplorer

![Logo](assets/images/logo.png)

🧙‍♂️ Magic-SigExplorer is a powerful tool designed to simplify the process of writing and managing Snort and Suricata rules. It allows users to write rules in a human-friendly YAML format, present them in a clean and intuitive UI using MkDocs, and then convert them back to the standard rule format as needed. This project is particularly useful for organizations and defenders who want to streamline their rule management process. 🛡️

### 🌟 Key Features

- **YAML Rule Writing** 📝: Write Snort and Suricata rules in an easy-to-understand YAML format. This feature makes rule writing more accessible and less error-prone.

- **Markdown Presentation** 📊: Present your rules in a clean and intuitive UI using MkDocs. This feature allows for better rule management and easier collaboration.

- **Rule Conversion** 🔄: Convert your YAML rules back to the standard Snort or Suricata rule format. This feature provides flexibility and ensures compatibility with existing systems.

- **Error Handling** 🚫: The project includes robust error handling to ensure smooth operation and ease of debugging.

- **Extensive Codebase** 💻: The project includes a comprehensive codebase with scripts for converting rules, generating markdown pages, and more.

To get started with Magic-SigExplorer, refer to the usage instructions in the How to use `runner.py` section of the README. 🚀

Remember, the ultimate goal of this project is to simplify the rule writing process by allowing rules to be written in YAML, presented in a user-friendly UI, and then converted back to the standard rule format as needed. Happy Hunting! 🎯


## Contribute

If you would like to contribute back to the public repo, add your rule to custom.rules, make sure your name is referenced, and PR it in. 

## How to use `runner.py`

`runner.py` is a script used to convert Snort and ET rules to YAML format and vice versa. Here's how to use it:

1. To convert Snort or ET rules to YAML format, use the `--convert` argument followed by the type of rules to convert. For example:
   ```
   python runner.py --convert snort
   ```
   This will convert the Snort rules located in `rule_files/snort3-community.rules` to YAML format and store them in `yaml/snort`.

2. If you want to convert the YAML files back to rule format, use the `--converttorule` argument. For example:
   ```
   python runner.py --convert snort --converttorule
   ```
   This will convert the YAML files in `yaml/snort` back to Snort rule format.

Please note that the rules are updated every Friday.

 
## Env Setup

### Installation

Before you start, ensure you have Poetry installed. If you don't, you can install it by running:

```
curl -sSL https://install.python-poetry.org | python -
```

### Setting up the Project

Once Poetry is installed, you can set up the project dependencies with:

`poetry install`


This command reads the `pyproject.toml` file from the current directory, resolves the dependencies, and installs them.

Now use the runner.py!