#!/usr/bin/python3
import os
import re
import nmap
import pynetbox
import sqlite3
from datetime import datetime
import warnings
from urllib3.exceptions import InsecureRequestWarning

from modules.config_parser import int_host, int_user, int_pass, ssh_password, ssh_keyfile_path, \
    nmap_ips_directory_path, netbox_url, netbox_token
from modules.exsi_vms import get_int_vms, get_qa_vms
from modules.functions import add_timestamp_to_filename, get_all_vms
from modules.vcenter_connection import con_vcenter

warnings.simplefilter('ignore', InsecureRequestWarning)

# NETBOX_URL = 'https://192.168.100.157'
# NETBOX_TOKEN = 'ce3860482cc0a5775e0243d4c10cc750e3ff0f43'


# Step 2: Get IP addresses from NetBox
def get_netbox_ips():
    nb = pynetbox.api(netbox_url, token=netbox_token)
    nb.http_session.verify = False

    ip_objects = nb.ipam.ip_addresses.all()
    netbox_ips = [ip.address.split('/')[0] for ip in ip_objects]
    return set(netbox_ips)  # Return as set for uniqueness


# Step 3: Get IPs from Nmap
def get_nmap_ips(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    nmap_ips = list(nm.all_hosts())
    return set(nmap_ips)  # Return as set for uniqueness


def create_daily_table():
    conn = sqlite3.connect('nmap_data.db')
    cursor = conn.cursor()

    current_date = datetime.now().strftime("%Y_%m_%d__%H_%M")
    table_name = f"nmap_records_{current_date}"

    # Create the daily table if it doesn't exist
    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS {table_name} (
        all_IP TEXT PRIMARY KEY,
        on_nmap BOOLEAN NOT NULL,
        on_netbox BOOLEAN NOT NULL,
        on_ignore_list BOOLEAN NOT NULL,
        comment TEXT
    )
    ''')

    conn.commit()
    conn.close()
    return table_name


def insert_or_update_ip_data(all_ip, nmap_ips, netbox_ips, table_name):
    conn = sqlite3.connect('nmap_data.db')
    cursor = conn.cursor()
    on_list = get_ignore_list()
    ip_to_add = []
    for ip in all_ip:
        on_ignoreL = ip in on_list
        on_netbox = ip in netbox_ips
        on_nmap = ip in nmap_ips
        if ip not in netbox_ips and ip not in on_list:
            ip_to_add.append(ip)
        # Insert or update (upsert) the IP information
        cursor.execute(f'''
        INSERT INTO {table_name} (all_IP, on_nmap, on_netbox, on_ignore_list, comment)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(all_IP)
        DO UPDATE SET on_nmap = excluded.on_nmap, 
                      on_netbox = excluded.on_netbox, 
                      on_ignore_list = excluded.on_ignore_list, 
                      comment = excluded.comment
        ''', (ip, on_nmap, on_netbox, on_ignoreL, 'Updated automatically'))

    conn.commit()
    conn.close()
    return ip_to_add



# Compile a list of all unique IPs
def get_all_unique_ips(netbox_ips, nmap_ips):
    all_ips = list(netbox_ips.union(nmap_ips))
    return all_ips


ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def get_vm_by_ip(vms, ip_address):
    for vm in vms:
        if vm.guest is not None and vm.guest.net:
            for nic in vm.guest.net:
                if nic.ipConfig is not None and nic.ipConfig.ipAddress:
                    for ip in nic.ipConfig.ipAddress:
                        if ip.ipAddress == ip_address:
                            return vm
    return None


def get_ignore_list():
    with open("./ignoreList.txt", "r") as lines:
        ips = []
        for line in lines:
            if not line or line.startswith('#') or not ip_pattern.match(line):
                continue
            ips.append(line.strip())
        return ips


def print_vm_details(vm):
    print(f"VM Name: {vm.summary.config.name}")
    print(f"VM Guest OS: {vm.summary.config.guestFullName}")
    print(f"VM Power State: {vm.runtime.powerState}")
    print(f"VM IP Address: {vm.guest.ipAddress}")
    print(f"VM Hostname: {vm.guest.hostName}")
    print("Network Interfaces:")
    for nic in vm.guest.net:
        print(f" - NIC Name: {nic.deviceConfigId}")

import os
import re

def extract_ips_from_file(filename):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            ips.extend(re.findall(ip_pattern, line))
    return ips

def categorize_ip(ip):
    # Categorize based on the IP address pattern
    if ip.startswith("192.168"):
        return "int"
    elif ip.startswith("10.110.110") or ip.startswith("10.111.1"):
        return "prod"
    else:
        return "qa"

def traverse_directory(directory_path):
    # Lists to store categorized IPs
    int_ips = []
    qa_ips = []
    prod_ips = []
    unique_ips = set()
    # Traverse the directory and categorize each IP
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            ips = extract_ips_from_file(file_path)
            unique_ips.update(ips)
            for ip in ips:
                category = categorize_ip(ip)
                if category == "int":
                    int_ips.append(ip)
                elif category == "prod":
                    prod_ips.append(ip)
                else:
                    qa_ips.append(ip)

    return unique_ips,int_ips, qa_ips, prod_ips

# Example usage
directory_path = '/path/to/only_IPs'





if __name__ == "__main__":
    keyfile_4k = ssh_keyfile_path
    password = ssh_password
    directory_path = nmap_ips_directory_path

    # Example network range for Nmap scan (modify as needed)
    network_range = '192.168.4.0/24'

    # Create the daily table (if not already created)
    daily_table_name = create_daily_table()

    # Get IPs from NetBox and Nmap
    netbox_ips = get_netbox_ips()
    nmap_ips ,int_ips,qa_ips,prod_ips = traverse_directory(directory_path)
    # print("INT IPs:", int_ips)
    # print("QA IPs:", qa_ips)
    # print("PROD IPs:", prod_ips)

    # Get all unique IPs from both NetBox and Nmap
    all_ips = get_all_unique_ips(netbox_ips, nmap_ips)

    # Insert or update the IPs in the daily table
    output = insert_or_update_ip_data(all_ips,nmap_ips, netbox_ips, daily_table_name)
    # print(output)
    int =[]
    qa =[]
    prod=[]

    for ip in output:
        category = categorize_ip(ip)
        if category == "int":
            int.append(ip)
        elif category == "prod":
            prod.append(ip)
        else:
            qa.append(ip)


    # print(int)
    # print(len(qa))
    # print("All unique IPs from NetBox and Nmap:")
    # for ip in all_ips:
    #     print(ip)

    # exit(0)
    # Example to use the vCenter connection and VM details
    # host = int_host
    # user = int_user
    # password = int_pass
    # con = con_vcenter(host=int_host, user=int_user, password=password)
    filename = 'vm_details.csv'
    final_filename = add_timestamp_to_filename(filename)
    # content = con.RetrieveContent()

    vms_int = get_int_vms()
    vms_qa = get_qa_vms()

    # password = int_pass
    # con = con_vcenter(host=int_host, user=int_user, password=password)
    # content = con.RetrieveContent()
    # vms_int = get_all_vms(content)
    # return vms_int

    # Write VM details for each IP found
    with open(final_filename, "w") as file:
        file.write(f"VM Name,IP Address,Hostname,OS\n")
        for ip in int:
            vm = get_vm_by_ip(vms_int, ip)
            if vm:
                file.write(
                    f"{vm.summary.config.name},{vm.guest.ipAddress},{vm.guest.hostName},{vm.summary.config.guestFullName}\n")
            else:
                file.write(f"ip not in ESXi,{ip},N/A,N/A\n")
                print(f"No VM found with IP address: {ip}")
        file.write("QA machines are : \n")

        for ip in qa:
            vm = get_vm_by_ip(vms_qa, ip)
            if vm:
                file.write(
                    f"{vm.summary.config.name},{vm.guest.ipAddress},{vm.guest.hostName},{vm.summary.config.guestFullName}\n")
            else:
                file.write(f"ip not in ESXi,{ip},N/A,N/A\n")
                print(f"No VM found with IP address: {ip}")
        file.write("Prod machines are : \n")