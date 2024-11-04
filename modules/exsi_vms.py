from modules.config_parser import int_host, int_user, int_pass, qa_host, qa_user, qa_pass
from modules.functions import add_timestamp_to_filename, get_all_vms
from modules.vcenter_connection import con_vcenter



def get_int_vms():

    con = con_vcenter(host=int_host, user=int_user, password=int_pass)
    content = con.RetrieveContent()
    vms_int = get_all_vms(content)
    return vms_int


def get_qa_vms():

    con = con_vcenter(host=qa_host, user=qa_user, password=qa_pass)
    content = con.RetrieveContent()
    vms_qa = get_all_vms(content)
    return vms_qa



