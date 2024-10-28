#!/usr/bin/python3
import os
import re

import nmap
import pynetbox
import sqlite3
from datetime import datetime
import warnings
from urllib3.exceptions import InsecureRequestWarning

from modules.config_parser import int_host, int_user, int_pass, env_cfg, ssh_password, ssh_keyfile_path, \
    nmap_ips_directory_path
from modules.functions import add_timestamp_to_filename, get_all_vms
from modules.vcenter_connection import con_vcenter

warnings.simplefilter('ignore', InsecureRequestWarning)

NETBOX_URL = 'https://192.168.100.157'
NETBOX_TOKEN = 'ce3860482cc0a5775e0243d4c10cc750e3ff0f43'
# Step 2: Get IP addresses from NetBox
def get_netbox_ips():
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = False

    ip_objects = nb.ipam.ip_addresses.all()
    netbox_ips = [ip.address.split('/')[0] for ip in ip_objects]
    return set(netbox_ips)

def get_nmap_ips(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    nmap_ips = list(nm.all_hosts())
    return nmap_ips

def create_daily_table():
    conn = sqlite3.connect('nmap_data.db')
    cursor = conn.cursor()

    current_date = datetime.now().strftime("%Y_%m_%d__%H_%M")
    # print(current_date)
    # exit()
    table_name = f"nmap_records_{current_date}"

    # Create the daily table if it doesn't exist
    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS {table_name} (
        nmap_IP TEXT PRIMARY KEY,
        on_netbox BOOLEAN NOT NULL,
        on_ignore_list BOOLEAN NOT NULL,
        comment TEXT
    )
    ''')

    conn.commit()
    conn.close()

    return table_name

def insert_or_update_ip_data(nmap_ips, netbox_ips, table_name):
    conn = sqlite3.connect('nmap_data.db')
    cursor = conn.cursor()
    on_list = get_ignore_list()
    ip_to_add = []
    for ip in nmap_ips:
        on_ignoreL = ip in on_list
        on_netbox = ip in netbox_ips
        if ip not in netbox_ips and ip not in on_list:
            ip_to_add.append(ip)
        # Insert or update (upsert) the IP information
        cursor.execute(f'''
        INSERT INTO {table_name} (nmap_IP, on_netbox, on_ignore_list, comment)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(nmap_IP)
        DO UPDATE SET on_netbox = excluded.on_netbox, on_ignore_list = excluded.on_ignore_list, comment = excluded.comment
        ''', (ip, on_netbox, on_ignoreL, 'Updated automatically'))

    conn.commit()
    conn.close()

    return ip_to_add



ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')



def get_vm_by_ip(service_instance, ip_address):
    # Get the content of the service instance
    content = service_instance.RetrieveContent()


    # Iterate through the VMs and check their network interfaces
    for vm in vms:
        if vm.guest is not None and vm.guest.net:
            for nic in vm.guest.net:
                if nic.ipConfig is not None and nic.ipConfig.ipAddress:
                    for ip in nic.ipConfig.ipAddress:
                        if ip.ipAddress == ip_address:
                            return vm
    return None

def get_ignore_list():
    # ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    with open("./ignoreList.txt", "r") as lines:
        ips = []
        for line in lines:

            if not line or line.startswith('#') or not ip_pattern.match(line):
                continue


            ips.append(line.strip())

        return ips



def get_vm_by_ip(vms, ip_address):
    # Get the content of the service instance

    for vm in vms:
        if vm.guest is not None and vm.guest.net:
            for nic in vm.guest.net:
                if nic.ipConfig is not None and nic.ipConfig.ipAddress:
                    for ip in nic.ipConfig.ipAddress:
                        if ip.ipAddress == ip_address:
                            return vm
    return None


def print_vm_details(vm):

    # Print details of the VM
    print(f"VM Name: {vm.summary.config.name}")
    print(f"VM Guest OS: {vm.summary.config.guestFullName}")
    print(f"VM Power State: {vm.runtime.powerState}")
    print(f"VM IP Address: {vm.guest.ipAddress}")
    print(f"VM Hostname: {vm.guest.hostName}")
    print("Network Interfaces:")
    for nic in vm.guest.net:
        print(f" - NIC Name: {nic.deviceConfigId}")
        # for ip in nic.ipConfig.ipAddress:
        #     print(f"   IP Address: {ip.ipAddress}")



######## ips extraction #######


def extract_ips_from_file(filename):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            ips.extend(re.findall(ip_pattern, line))
    return ips

def traverse_directory(directory_path):

    unique_ips = set()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            ips = extract_ips_from_file(file_path)
            unique_ips.update(ips)

    return unique_ips
#######


if __name__ == "__main__":
    keyfile_4k = ssh_keyfile_path
    password = ssh_password
    directory_path = nmap_ips_directory_path

    # Example network range for Nmap scan (modify as needed)
    network_range = '192.168.4.0/24'

    # Create the daily table (if not already created)
    daily_table_name = create_daily_table()

    # Get IPs from Nmap and NetBox
    netbox_ips = get_netbox_ips()
    # nmap_ips = get_nmap_ips(network_range)
    nmap_ips= traverse_directory(directory_path)

    # Insert or update the IPs in the daily table
    output = insert_or_update_ip_data(nmap_ips, netbox_ips, daily_table_name)

    print(f"Processed {len(nmap_ips)} IPs from Nmap. Inserted/Updated into the table {daily_table_name}.")

    print("ips should be on netbox :")
    for i in output:
        print(i)

    # if env_cfg == 'INT':
    host = int_host
    user = int_user
    password = int_pass
    con = con_vcenter(host=int_host, user=int_user, password=password)
    filename = 'vm_details.csv'
    final_filename = add_timestamp_to_filename(filename)
    print(final_filename)
    content = con.RetrieveContent()


    def is_ipv4(address):
        return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', address) is not None


    vms = get_all_vms(content)

    with open(final_filename, "w") as file:
        file.write(
            f"{'VM Name'},{'IP Address'},{'Hostname'},{'OS'}\n")

        for i in output:
            vm = get_vm_by_ip(vms, i)
            if vm:
                file.write(
                    f"{vm.summary.config.name},{vm.guest.ipAddress},{vm.guest.hostName},{vm.summary.config.guestFullName}\n")
            else:
                file.write(
                    f"{"ip not in exsi"},{i},{"N/A"},{"N/A"}\n")
                print(f"No VM found with IP address: {i}")










