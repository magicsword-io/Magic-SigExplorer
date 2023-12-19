import os
from jinja2 import Environment, FileSystemLoader
import yaml

def convert_yaml_to_md(yaml_dir='yaml/', template_dir='bin/jinja2_templates', output_dir='app/content/rules'):
    if not os.path.exists(yaml_dir):
        raise FileNotFoundError(f"Directory {yaml_dir} does not exist.")
    if not os.path.exists(template_dir):
        raise FileNotFoundError(f"Directory {template_dir} does not exist.")
    if os.path.exists(output_dir):
        for file in os.scandir(output_dir):
            os.remove(file.path)
    else:
        os.makedirs(output_dir)

    env = Environment(loader=FileSystemLoader(template_dir))
    for filename in os.listdir(yaml_dir):
        if filename.endswith('.yaml'):
            try:
                with open(os.path.join(yaml_dir, filename), 'r') as file:
                    data = yaml.safe_load(file)
            except Exception as e:
                print(f"Error loading file {filename}: {str(e)}")
                continue
            try:
                template = env.get_template('rule.md.j2')
            except Exception as e:
                print(f"Error loading template: {str(e)}")
                continue

            if isinstance(data, list):
                for item in data:
                    rule = item['rule']
                    print(f"Rule dictionary: {rule}")
                    try:
                        markdown = template.render(rule=rule)
                    except Exception as e:
                        print(f"Error rendering template: {str(e)}")
                        continue

                    md_filename = filename.replace('.yaml', '.md')
                    try:
                        with open(os.path.join(output_dir, md_filename), 'w') as file:
                            file.write(markdown)
                    except Exception as e:
                        print(f"Error writing to file {md_filename}: {str(e)}")