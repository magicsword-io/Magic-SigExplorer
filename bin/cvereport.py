import yaml
import re
import os
from jinja2 import Environment, FileSystemLoader

def extract_cve_data(yaml_dir):
    cve_dict = {}
    for root, dirs, files in os.walk(yaml_dir):
        for file in files:
            if file.endswith(".yaml"):
                rule_type = os.path.basename(root)
                with open(os.path.join(root, file), 'r') as stream:
                    try:
                        yaml_data = yaml.safe_load(stream)
                        for rule_dict in yaml_data:
                            rule = rule_dict['rule']
                            cve = None
                            if 'msg' in rule.get('details', {}):
                                cve_match = re.search(r"CVE-\d{4}-\d+", rule['details']['msg'])
                                if cve_match:
                                    cve = cve_match.group(0)
                            if not cve and 'reference' in rule['details']:
                                ref = rule['details']['reference']
                                if ref.startswith('cve,'):
                                    cve_match = re.search(r"cve,(\d{4}-\d+)", ref, re.IGNORECASE)
                                    if cve_match:
                                        cve = "CVE-" + cve_match.group(0).split(',')[1]
                            if cve:
                                if cve not in cve_dict:
                                    cve_dict[cve] = []
                                rule['rule_type'] = rule_type
                                if rule not in cve_dict[cve]:
                                    cve_dict[cve].append(rule)
                    except yaml.YAMLError as exc:
                        print(exc)
    return cve_dict


def render_template(cve_data, output_path):
    file_loader = FileSystemLoader('bin/jinja2_templates')
    env = Environment(loader=file_loader)
    template = env.get_template('cve_report.md.j2')
    output = template.render(cves=cve_data)
    with open(os.path.join(output_path, 'cve_report.md'), 'w') as f:
        f.write(output)

def main():
    yaml_dir = 'yaml'
    output_path = 'Magic-SigExplorer/docs'
    cve_data = extract_cve_data(yaml_dir)
    cve_data = dict(sorted(cve_data.items(), key=lambda item: item[0], reverse=True))
    render_template(cve_data, output_path)

if __name__ == "__main__":
    main()