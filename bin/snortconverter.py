import re
import yaml
import os

def parse_snort_rule(rule):
    # Standard rule pattern
    rule_pattern = r'alert\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)'
    rule_match = re.match(rule_pattern, rule.strip())
    if rule_match:
        return extract_rule_data(rule_match)
    return handle_special_cases(rule)

def handle_special_cases(rule):
    # Bidirectional traffic pattern
    bidirectional_pattern = r'alert\s+(\w+)\s+([^\s]+)\s+<>+\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)'
    bidirectional_match = re.match(bidirectional_pattern, rule.strip())
    if bidirectional_match:
        return extract_rule_data(bidirectional_match)

    # HTTP-specific rules pattern
    http_pattern = r'alert http \((.*)\)'
    http_match = re.match(http_pattern, rule.strip())
    if http_match:
        return extract_http_rule_data(http_match.groups()[0], 'http')

    # ICMP-specific rules pattern
    icmp_pattern = r'alert icmp (.*)'
    icmp_match = re.match(icmp_pattern, rule.strip())
    if icmp_match:
        return extract_icmp_rule_data(icmp_match.groups()[0], 'icmp')

    # SSL-specific rules pattern
    ssl_pattern = r'alert ssl (.*)'
    ssl_match = re.match(ssl_pattern, rule.strip())
    if ssl_match:
        return extract_ssl_rule_data(ssl_match.groups()[0], 'ssl')
    return None
def extract_rule_data(match):
    protocol, src_net, src_port, dst_net, dst_port, options = match.groups()
    options_dict = parse_options(options)
    return {
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

def extract_http_rule_data(options, protocol):
    options_dict = parse_options(options)
    return {
        'rule': {
            'protocol': protocol,
            'details': options_dict
        }
    }

def extract_icmp_rule_data(options, protocol):
    options_dict = parse_options(options)
    return {
        'rule': {
            'protocol': protocol,
            'details': options_dict
        }
    }

def extract_ssl_rule_data(options, protocol):
    options_dict = parse_options(options)
    return {
        'rule': {
            'protocol': protocol,
            'details': options_dict
        }
    }

def parse_options(options_string):
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

def convert_rules_to_yaml(input_file, output_dir, converter_type=None):
    successful, failed = 0, 0
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        with open(input_file, 'r') as file:
            rules = file.readlines()

        for i, rule in enumerate(rules):
            rule = rule.strip()
            if not rule or rule.startswith('#'):
                continue

            yaml_data = parse_snort_rule(rule)
            if yaml_data:
                sid = yaml_data['rule']['details'].get('sid', f"unknown_sid_{i+1}")
                output_file = os.path.join(output_dir, f"snort_rule_{sid}.yaml")
                with open(output_file, 'w') as outfile:
                    yaml.dump([yaml_data], outfile, default_flow_style=False)
                successful += 1
            else:
                print(f"Rule {i+1} could not be converted: {rule}")
                failed += 1

    except Exception as e:
        print(f"An error occurred: {e}")
        return successful, failed

    print(f"Successfully converted {successful} rules. Failed to convert {failed} rules.")
    return successful, failed

def main():
    input_file = 'snort3-community.rules'
    output_dir = 'yaml/'
    convert_rules_to_yaml(input_file, output_dir)

if __name__ == "__main__":
    main()