import re
import yaml
import os

def parse_suricata_rule(rule):
    #print("Parsing Suricata rule...")
    rule_pattern = r'alert\s+([\w|-]+)\s+([^\s]+)\s+([^\s]+)\s+(<>|->)\s+([^\s]+)\s+([^\s]+)?\s+\((.*)\)'
    rule_match = re.match(rule_pattern, rule.strip())
    if not rule_match:
        #print("Suricata Rule pattern not matched:", rule)
        return None

    protocol, src_net, src_port, direction, dst_net, dst_port, options = rule_match.groups()
    options_dict = parse_suricata_options(options)

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

def parse_suricata_options(options_string):
    #print("Parsing Suricata options...")
    options_dict = {}
    options = options_string.split(';')

    for option in options:
        if ':' in option:
            key, value = option.split(':', 1)
            options_dict[key.strip()] = value.strip()

    return options_dict

def parse_suricata_tcp_pkt_rule(rule):
    #print("Parsing Suricata tcp-pkt rule...")
    rule_pattern = r'alert\s+tcp-pkt\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)'
    rule_match = re.match(rule_pattern, rule.strip())

    if not rule_match:
        #print("Suricata tcp-pkt Rule pattern not matched:", rule)
        return None

    src_net, src_port, dst_net, dst_port, options = rule_match.groups()
    options_dict = parse_suricata_options(options)

    yaml_data = {
        'rule': {
            'protocol': 'tcp-pkt',
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

def convert_suricata_rules(input_file, output_dir):
    #print("Converting Suricata rules...")
    with open(input_file, 'r') as infile:
        rules = infile.readlines()

    successful = 0
    failed = 0

    for i, rule in enumerate(rules):
        rule = rule.strip()
        if not rule or rule.startswith('#'):
            continue

        if 'tcp-pkt' in rule:
            yaml_data = parse_suricata_tcp_pkt_rule(rule)
        else:
            yaml_data = parse_suricata_rule(rule)

        if yaml_data:
            sid = yaml_data['rule']['details'].get('sid')
            output_file_name = f"suricata_rule_{sid}.yaml" if sid else f"suricata_rule_unknown_sid_{i+1}.yaml"
            output_file = os.path.join(output_dir, output_file_name)
            with open(output_file, 'w') as outfile:
                yaml.dump([yaml_data], outfile, default_flow_style=False)
            successful += 1
        else:
            print(f"Suricata Rule {i+1} could not be converted.")
            failed += 1

    print(f"Conversion completed. {successful} rules converted successfully, {failed} rules failed to convert.")
    return successful, failed