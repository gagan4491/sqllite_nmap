from pyvim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl



def con_vcenter(host=None, user=None, password=None):
    host = host
    user = user
    password = password

    if 'n/a' in (host.lower(), user.lower(), password.lower()):
        print("One or more fields are 'N/A' or 'n/a'.")
        print("Please update the correct credentials in the conf.cnf file ")
        exit(0)

    port = 443

    context = ssl._create_unverified_context()

    si = SmartConnect(host=host, user=user, pwd=password, port=port, sslContext=context)

    return si
