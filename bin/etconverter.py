import re
import yaml
import os

def parse_et_rule(rule):
    rule_pattern = r'alert\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)'
    rule_match = re.match(rule_pattern, rule.strip())

    if not rule_match:
        print("ET Rule pattern not matched:", rule)
        return None

    protocol, src_net, src_port, dst_net, dst_port, options = rule_match.groups()
    options_dict = parse_et_options(options)

    yaml_data = {
        'rule': {
            'protocol': protocol,
            'source': {
                'network': src_net,
                'port': src_port
            },
            'destination': {
                'network': dst_net,
                'port': dst_port
            },
            'details': options_dict
        }
    }

    return yaml_data

def parse_et_options(options_string):
    options_dict = {}
    options = options_string.split(';')
    content_dict = {}

    for option in options:
        if ':' in option:
            key, value = option.split(':', 1)
            key = key.strip()
            value = value.strip()

            if key == 'content':
                if content_dict:
                    options_dict.setdefault('contents', []).append(content_dict)
                    content_dict = {}
                content_dict['value'] = value
            elif key in ['depth', 'offset']:
                content_dict[key] = value
            else:
                if content_dict:
                    options_dict.setdefault('contents', []).append(content_dict)
                    content_dict = {}
                options_dict[key] = value
        else:
            special_option = option.strip()
            if special_option:
                options_dict.setdefault('special_options', []).append(special_option)

    if content_dict:
        options_dict.setdefault('contents', []).append(content_dict)

    return options_dict

def parse_content(value):
    content_dict = {'value': value}
    return content_dict

def convert_et_rules_to_yaml(input_file, output_dir, converter_type=None):
    successful, failed = 0, 0
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        with open(input_file, 'r') as file:
            rules = file.readlines()
    except Exception as e:
        print(f"Failed to read the file: {e}")
        return successful, failed

    for i, rule in enumerate(rules):
        rule = rule.strip()
        if not rule or rule.startswith('#'):
            continue

        yaml_data = parse_et_rule(rule)
        if yaml_data:
            sid = yaml_data['rule']['details'].get('sid')
            output_file_name = f"{converter_type}_rule_{sid}.yaml" if sid else f"{converter_type}_unknown_sid_{i+1}.yaml"
            output_file = os.path.join(output_dir, output_file_name)
            with open(output_file, 'w') as outfile:
                yaml.dump([yaml_data], outfile, default_flow_style=False)
            successful += 1
        else:
            print(f"ET Rule {i+1} could not be converted.")
            failed += 1

    return successful, failed

