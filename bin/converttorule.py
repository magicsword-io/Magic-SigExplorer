import yaml
import os

def convert_yaml_to_rules(input_dir, output_file):
    successful, failed = 0, 0
    if not os.path.exists(input_dir):
        print(f"Directory {input_dir} does not exist.")
        return successful, failed

    try:
        with open(output_file, 'w') as outfile:
            for i, filename in enumerate(os.listdir(input_dir), start=1):
                if filename.endswith('.yaml'):
                    try:
                        with open(os.path.join(input_dir, filename), 'r') as infile:
                            yaml_data = yaml.safe_load(infile)
                            rule = convert_yaml_to_rule(yaml_data[0]['rule'])
                            outfile.write(rule + '\n')
                            successful += 1
                    except Exception as e:
                        print(f"Failed to convert YAML {filename} to rule: {e}")
                        failed += 1
    except Exception as e:
        print(f"Failed to write to the file: {e}")
        failed += 1

    return successful, failed

def convert_yaml_to_rule(yaml_data):
    protocol = yaml_data['protocol']
    source = yaml_data['source'] if 'source' in yaml_data else None
    destination = yaml_data['destination'] if 'destination' in yaml_data else None
    options = convert_options_to_string(yaml_data['details'])

    if source and destination:
        source_str = f"{source['network']} {source['port']}"
        destination_str = f"{destination['network']} {destination['port']}"
        return f"alert {protocol} {source_str} -> {destination_str} ({options})"
    else:
        return f"alert {protocol} ({options})"

def convert_options_to_string(options):
    options_string = []
    if isinstance(options, dict):
        for key, value in options.items():
            if key == 'contents':
                for content in value:
                    options_string.append(convert_content_to_string(content))
            elif key == 'metadata':
                options_string.append(f"{key}:{value}")
            else:
                if isinstance(value, list):
                    options_string.append(f"{key}:{','.join(value)}")
                else:
                    options_string.append(f"{key}:{value}")
    return '; '.join(options_string)

def convert_content_to_string(content):
    content_string = []
    for key, value in content.items():
        if key == 'value':
            content_string.append(value)
        else:
            content_string.append(f"{key}:{value}")
    return "content:" + ";".join(content_string)


if __name__ == "__main__":
    input_dir = 'yaml/'
    output_file = 'rules/community-rules.rules'
    convert_yaml_to_rules(input_dir, output_file)