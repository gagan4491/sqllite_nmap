import configparser


import argparse



config = configparser.RawConfigParser()
config.read('config.cnf')
try:
    env_cfg =  config.get('environment', 'environment').strip()

    ssh_keyfile_path = config.get('keyfile', 'ssh_keyfile_path').strip()
    ssh_password = config.get('root', 'ssh_password').strip()
    ssh_default_port = config.get('root', 'ssh_port').strip()

    int_host = config['INT']['int_host'].strip()
    int_user = config['INT']['user'].strip()
    int_pass = str(config['INT']['pass']).strip()
    qa_host = config['QA']['qa_host'].strip()
    qa_user = config['QA']['user'].strip()
    qa_pass = config['QA']['pass'].strip()
    prod_host = config['PROD']['prod_host'].strip()
    prod_user = config['PROD']['user'].strip()
    prod_pass = config['PROD']['pass'].strip()
except Exception as e:
    print(e)
    print(" please verify the config file if its all correct .")