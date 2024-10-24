#!/usr/bin/python3

import os
from datetime import datetime

from pyVmomi import vim

def get_all_vms(content):
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    return container.view




def add_timestamp_to_filename(filename):
    # Get the current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Split the file name into name and extension
    base, extension = os.path.splitext(filename)

    # Create the new file name with the timestamp
    new_filename = f"{base}_{timestamp}{extension}"

    return new_filename
