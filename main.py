import nmap
import pynetbox
import sqlite3

# Step 1: Define NetBox and Nmap settings
NETBOX_URL = 'https://192.168.100.157'
NETBOX_TOKEN = 'ce3860482cc0a5775e0243d4c10cc750e3ff0f43'
# nb.http_session.verify = False

# Step 2: Get IP addresses from NetBox
def get_netbox_ips():
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = False
    ip_objects = nb.ipam.ip_addresses.all()
    netbox_ips = [ip.address.split('/')[0] for ip in ip_objects]  # Extract IPs without the CIDR suffix
    return set(netbox_ips)

# Step 3: Get IP addresses from Nmap
def get_nmap_ips(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')  # Perform a ping scan
    nmap_ips = list(nm.all_hosts())
    return nmap_ips

# Step 4: Insert IPs into the database
def insert_ip_data(nmap_ips, netbox_ips):
    conn = sqlite3.connect('nmap_data.db')
    cursor = conn.cursor()

    for ip in nmap_ips:
        on_netbox = ip in netbox_ips
        cursor.execute('''
        INSERT INTO nmap_records (nmap_IP, on_netbox, on_ignore_list, comment)
        VALUES (?, ?, ?, ?)
        ''', (ip, on_netbox, False, 'Automatically added'))

    conn.commit()
    conn.close()

# Step 5: Main logic to run the entire process
if __name__ == "__main__":
    # Example network range for Nmap scan (modify as needed)
    network_range = '192.168.4.0/24'

    # Get IPs from Nmap and NetBox
    netbox_ips = get_netbox_ips()
    nmap_ips = get_nmap_ips(network_range)

    # Insert the IPs into the database
    insert_ip_data(nmap_ips, netbox_ips)

    print(f"Processed {len(nmap_ips)} IPs from Nmap. Inserted into the database.")
