# Magic-SigExplorer

![Logo](assets/images/logo.png)

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

### Running the Project

To run the `runner.py` script with Poetry, you can use the `poetry run` command:

`poetry run python runner.py --convert snort`


This will run the script in the virtual environment that Poetry has set up for your project.

### Updating Dependencies

If the dependencies of the project need to be updated, you can use:

`poetry update`


This will update all dependencies to their latest versions.

### Adding Dependencies

If you need to add a dependency to the project, you can use:

`poetry add <dependency>`

Replace `<dependency>` with the name of the dependency you want to add. This will add the dependency to `pyproject.toml` and install it.
