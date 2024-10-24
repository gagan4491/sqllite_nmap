import csv
#
# Read the CSV file and update hostnames in NetBox
with open('../vm_details.csv', mode='r') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        ip = row['IP Address'].strip()
        hostname = row['Hostname'].strip()

        print(ip,hostname)
        # update_hostname_in_netbox(vm_name, hostname)


