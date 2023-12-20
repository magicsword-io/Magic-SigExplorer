import hashlib
import os
import requests
import tarfile
import shutil

def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            return hashlib.sha256(file.read()).hexdigest()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def download_file(url, file_path):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file from {url}: {e}")
    except Exception as e:
        print(f"Error saving file to {file_path}: {e}")
    return False

def main():
    rules = [
        {
            'url': 'https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules',
            'file_path': 'rule_files/emerging-all.rules'
        },
        {
            'url': 'https://www.snort.org/downloads/community/community-rules.tar.gz',
            'file_path': 'rule_files/community-rules.tar.gz',
            'is_tar': True
        },
        {
            'url': 'https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules',
            'file_path': 'rule_files/suricata-emerging-all.rules'  # New rule
        }
    ]

    for rule in rules:
        file_exists = os.path.exists(rule['file_path'])
        old_hash = get_file_hash(rule['file_path']) if file_exists else None

        if not file_exists or old_hash is not None:
            if download_file(rule['url'], rule['file_path']):
                new_hash = get_file_hash(rule['file_path'])

                if not file_exists or old_hash != new_hash:
                    print(f"File {rule['file_path']} downloaded and updated.")
                    print(f"Old hash: {old_hash}")
                    print(f"New hash: {new_hash}")
                    if rule.get('is_tar', False):
                        try:
                            with tarfile.open(rule['file_path'], 'r:gz') as tar:
                                tar.extractall(path='rule_files/')
                            print(f"Extracted {rule['file_path']}")
                            extracted_dir = 'rule_files/community-rules'
                            if os.path.isdir(extracted_dir):
                                shutil.rmtree(extracted_dir)
                            os.remove(rule['file_path'])
                            print(f"Cleaned up extracted files and {rule['file_path']}")
                        except tarfile.ReadError as e:
                            print(f"Error extracting tar file {rule['file_path']}: {e}")
                else:
                    print(f"No update needed for {rule['file_path']}.")
            else:
                print(f"Skipping update for {rule['file_path']} due to download error.")
        else:
            print(f"Error occurred with file {rule['file_path']}. Exiting.")
            break
if __name__ == '__main__':
    main()