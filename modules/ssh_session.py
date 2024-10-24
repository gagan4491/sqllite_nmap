import paramiko

from modules.config_parser import ssh_default_port


def create_ssh_session(hostname, keyfile_4k=None, password=None, username='root'):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth = None

    try:
        if keyfile_4k:
            try:
                # print(keyfile_4k)
                key = paramiko.RSAKey.from_private_key_file(keyfile_4k)
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                client.connect(hostname, port=ssh_default_port, username=username, pkey=key,
                               disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]))
                if client.get_transport() and client.get_transport().is_active():
                    auth = '4k'
                    return client, auth
                else:
                    client.close()
            except paramiko.ssh_exception.AuthenticationException:
                print(f"4k key failed for {hostname}")

        if password:
            try:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                client.connect(hostname, port=ssh_default_port, username=username, password=password)
                if client.get_transport() and client.get_transport().is_active():
                    auth = 'password'
                    return client, auth
                else:
                    client.close()
            except paramiko.ssh_exception.AuthenticationException:
                print(f"Password failed for {hostname}")

    except paramiko.ssh_exception.SSHException as ssh_ex:
        print("Error connecting to the SSH server:", str(ssh_ex))

    return None, None
