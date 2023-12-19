import os
import yaml
from jinja2 import Environment, FileSystemLoader

def generate_md_from_classtype(yaml_dir, template_dir, output_dir):
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('classtype.md.j2')

    classtypes = {}
    for file_name in os.listdir(yaml_dir):
        if file_name.endswith('.yaml'):
            with open(os.path.join(yaml_dir, file_name), 'r') as file:
                for rule_list in yaml.safe_load_all(file):  
                    for rule in rule_list:
                        if isinstance(rule, dict) and 'rule' in rule and isinstance(rule['rule'], dict) and 'details' in rule['rule']:
                            if 'classtype' in rule['rule']['details'] and 'sid' in rule['rule']['details']:
                                classtype = rule['rule']['details']['classtype']
                                if classtype not in classtypes:
                                    classtypes[classtype] = []
                                classtypes[classtype].append(rule['rule']['details'])
                        else:
                            print(f"Unexpected rule format in file {file_name}: {rule}")

def generate_md_from_rule(yaml_dir, template_dir, output_dir, converter_type):
    env = Environment(loader=FileSystemLoader(template_dir))
    rule_template = env.get_template('rule_detail.md.j2')
    classtype_template = env.get_template('classtype.md.j2')

    classtypes = {}
    for file_name in os.listdir(yaml_dir):
        if file_name.endswith('.yaml'):
            with open(os.path.join(yaml_dir, file_name), 'r') as file:
                for rule_list in yaml.safe_load_all(file):
                    for rule in rule_list:  # Add this line
                        if isinstance(rule, dict) and 'rule' in rule:
                            output_file = os.path.join(output_dir, f"{file_name.replace('.yaml', '.md')}")
                            os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Create directory if it doesn't exist
                            with open(output_file, 'w') as outfile:
                                sid = rule['rule']['details'].get('sid', 'unknown_sid')
                                source_link = f"https://github.com/magicsword-io/Magic-SigExplorer/tree/main/yaml/{converter_type}/{converter_type}_rule_{sid}.yaml"
                                rendered_template = rule_template.render(rule=rule['rule'], rule_type=converter_type, source_link=source_link)
                                outfile.write(rendered_template)
                            if 'details' in rule['rule'] and 'classtype' in rule['rule']['details']:
                                classtype = rule['rule']['details']['classtype']
                                if classtype not in classtypes:
                                    classtypes[classtype] = []
                                classtypes[classtype].append(rule['rule']['details'])
    if 'snort' in yaml_dir:
        output_file = os.path.join(output_dir, '../../snort.md')
        rule_type = 'snort'
    elif 'et' in yaml_dir:
        output_file = os.path.join(output_dir, '../../et.md')
        rule_type = 'et'
    elif 'suricata' in yaml_dir:  # New condition for suricata
        output_file = os.path.join(output_dir, '../../suricata.md')
        rule_type = 'suricata'
    elif 'custom' in yaml_dir:  # New condition for custom
        output_file = os.path.join(output_dir, '../../custom.md')
        rule_type = 'custom'
    else:
        print(f"Unknown directory: {yaml_dir}")
        return

    with open(output_file, 'w') as file:
        rendered_template = classtype_template.render(classtypes=classtypes, header=f'{rule_type.capitalize()} Rules', rule_type=rule_type)
        file.write(rendered_template)