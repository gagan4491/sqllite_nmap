import os
import re

from modules.config_parser import nmap_ips_directory_path


def extract_ips_from_file(filename):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            ips.extend(re.findall(ip_pattern, line))
    return ips

def traverse_directory(directory_path):
    print(directory_path)
    unique_ips = set()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            ips = extract_ips_from_file(file_path)
            unique_ips.update(ips)

    return unique_ips


directory_path = os.path.normpath(nmap_ips_directory_path)
# print(repr(directory_path))

unique_ip_list = traverse_directory(directory_path)

# Print the unique IP addresses
for ip in unique_ip_list:
    print(ip)