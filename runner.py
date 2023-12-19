import argparse
import bin.snortconverter as snortconverter
import bin.etconverter as etconverter
import bin.etsuricataconverter as etsuricataconverter
from bin.converttorule import convert_yaml_to_rules
from bin.converttomd import convert_yaml_to_md
from bin.createmdpage import generate_md_from_classtype
from bin.createmdpage import generate_md_from_rule

def convert_rules(file_name, output_dir, converter_type):
    converters = {
        'snort': snortconverter.convert_rules_to_yaml,
        'et': etconverter.convert_et_rules_to_yaml,
        'suricata': etsuricataconverter.convert_suricata_rules,
        'custom': etconverter.convert_et_rules_to_yaml
    }

    converter = converters.get(converter_type)
    if converter:
        print(f"Starting {converter_type.capitalize()} conversion...")
        try:
            successful, failed = converter(file_name, output_dir, converter_type)
            print(f"{converter_type.capitalize()} conversion: {successful} successful, {failed} failed")
        except Exception as e:
            print(f"Error during {converter_type.capitalize()} conversion: {str(e)}")
            successful, failed = 0, 0
    else:
        print(f"Invalid converter type: {converter_type}")
        successful, failed = 0, 0

def main():
    parser = argparse.ArgumentParser(description='Convert Snort, ET, Suricata, and Custom rules to YAML format.')
    parser.add_argument('--convert', choices=['snort', 'et', 'suricata', 'custom'], required=True, help='Specify the type of rules to convert: snort, et, suricata, or custom')
    parser.add_argument('--converttorule', action='store_true', help='Convert YAML files back to rule format')

    args = parser.parse_args()
    converter_type = args.convert

    files_to_convert = {'snort': 'rule_files/snort3-community.rules', 'et': 'rule_files/emerging-all.rules', 'suricata': 'rule_files/suricata-emerging-all.rules', 'custom': 'rule_files/custom.rules'}
    yaml_output_dirs = {'snort': 'yaml/snort', 'et': 'yaml/et', 'suricata': 'yaml/suricata', 'custom': 'yaml/custom'}
    md_output_dirs = {'snort': 'Magic-SigExplorer/docs/rules/snort', 'et': 'Magic-SigExplorer/docs/rules/et', 'suricata': 'Magic-SigExplorer/docs/rules/suricata', 'custom': 'Magic-SigExplorer/docs/rules/custom'}
    output_rule_files = {'snort': 'rules/snort-rules.rules', 'et': 'rules/et-rules.rules', 'suricata': 'rules/suricata-rules.rules', 'custom': 'rules/custom-rules.rules'}

    file_to_convert = files_to_convert.get(converter_type)
    yaml_output_dir = yaml_output_dirs.get(converter_type)
    md_output_dir = md_output_dirs.get(converter_type)
    output_rule_file = output_rule_files.get(converter_type)

    if file_to_convert and yaml_output_dir and md_output_dir:
        print(f"Starting conversion for {converter_type}...")
        convert_rules(file_to_convert, yaml_output_dir, converter_type)
        print("Conversion to YAML completed. Starting conversion to Markdown...")
        generate_md_from_rule(yaml_output_dir, 'bin/jinja2_templates', md_output_dir, converter_type)
        print("Conversion to Markdown completed. Generating Markdown from classtype...")
        generate_md_from_classtype(yaml_output_dir, 'bin/jinja2_templates', md_output_dir)
        print("Markdown generation completed.")

        if args.converttorule and output_rule_file:
            print("Converting YAML files back to rule format...")
            convert_yaml_to_rules(yaml_output_dir, output_rule_file)
            print("Conversion back to rule format completed.")
    else:
        print(f"Missing required data for conversion type: {converter_type}")


if __name__ == "__main__":
    main()