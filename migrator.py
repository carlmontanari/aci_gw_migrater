import argparse
import getpass
import ipaddress
import logging
import os
import re
import sys
import time
from acipdt import acipdt
import pandas
from netmiko import ConnectHandler
from multiprocessing import Pool
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

"""
PLEASE SEE "gw_exists" function for important note!
"""

# Disable requests insecure warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Static user/password for testing purposes; should be left to None generally!
USERNAME = None
PASSWORD = None

# Static "legacy" Core device tuples (netmiko device type, ip)
# REPLACE THIS WITH VALUES FOR YOUR ENVIRONMENT
LEGACY_DEVICES = [('cisco_ios', 'X.X.X.X')]

# Timeout Values
NETMIKO_TIMEOUT = 10

# Max connections to "legacy" devices
MAX_CONNS = 4

# Static ACI device info
ACI_HOST = 'X.X.X.X'
ACI_USERNAME = None
ACI_PASSWORD = None
SNAPSHOT = True
SNAPSHOT_FILE_NAME = 'aci_gw_migrator'

# CSV COLUMNS
CSV_COLUMNS = ['Gateway', 'SubnetMask', 'Tenant', 'AppProfile', 'EPG', 'BD']

# Setup Logging, File Handler, Stdout, Path
LOGGING_FH_LEVEL = 'DEBUG'
LOGGING_STDOUT_LEVEL = 'CRITICAL'
LOGGING_PATH = os.getcwd()

LOGGER = logging.getLogger('aci_migrator')
LOGGER.setLevel(logging.DEBUG)

FH = logging.FileHandler('{}/{}.log'.format(LOGGING_PATH, 'aci_migrator'),
                         mode='w')
eval(f'FH.setLevel(logging.{LOGGING_FH_LEVEL})')
fhformat = logging.Formatter("%(levelname)s, %(asctime)s,"
                             "\n\tFunction: %(funcName)s, "
                             "Line: %(lineno)d, \n\tMessage: "
                             "%(message)s\n")
FH.setFormatter(fhformat)

CH = logging.StreamHandler()
eval(f'CH.setLevel(logging.{LOGGING_STDOUT_LEVEL})')
chformat = logging.Formatter("%(message)s")
CH.setFormatter(chformat)

LOGGER.addHandler(FH)
LOGGER.addHandler(CH)


def vlan(vl_id):
    """Connect to IOS-XE Device

    Args:
        vl_id

    Returns:
        vl_id (as integer)

    Raises:
        ArgumentTypeError if invalid VLAN ID
    """
    LOGGER.debug(f'Parsing VLAN ID {vl_id}.')
    vl_id = int(vl_id)
    if vl_id < 0 or vl_id > 4094:
        LOGGER.critical(f'ERROR: VLAN ID {vl_id} is invalid, exiting.')
        raise argparse.ArgumentTypeError('Invalid VLAN ID.')
    LOGGER.debug(f'VLAN ID {vl_id} validated, moving on.')
    return(vl_id)


def continue_or_exit(msg=None):
    """Prompt user to exit script (default) or continue

    Args:
        N/A

    Kwargs:
        msg (optional): Message to display to user

    Returns:
        None or exits script
    """
    if msg:
        LOGGER.critical(msg)

    LOGGER.debug('Prompting user to continue or exit.')
    while True:
        user_input = input("Would you like to continue, 'y' or 'n' [n]: ")
        selection = user_input or 'n'
        if selection.lower() == 'n':
            LOGGER.debug('User decided to exit. Exiting.')
            sys.exit(0)
        elif selection.lower() == 'y':
            LOGGER.debug('User decided to continue. Moving on.')
            return(None)


def connect(user, password, dev, ip):
    """Connect to Network Device

    Args:
        user (str)
        password (str)
        dev (str) (netmiko device_type)
        ip (str) (valid ipv4 address)

    Returns:
        conn (Netmiko Connection Object)
    """
    device_info = {'device_type': dev,
                   'ip': ip,
                   'username': user,
                   'password': password,
                   'timeout': NETMIKO_TIMEOUT}
    LOGGER.debug('Attempting to connect to device with the following info:\n'
                 f'\tDevice Type: {device_info["device_type"]}\n'
                 f'\tIP: {device_info["ip"]}\n'
                 f'\tUsername: {device_info["username"]}')
    try:
        conn = ConnectHandler(**device_info)
        LOGGER.info(f'Connected to device {device_info["ip"]} successfully!')
        return(conn)
    except Exception as e:
        LOGGER.critical('Encountered an error connect to device '
                        f'{device_info["ip"]}, exiting. Error {e}')
        print('Encountered an error connecting to device '
              f'{device_info["ip"]}, exiting. Error: {e}')
        sys.exit(1)


def gw_exists(conn, gw):
    """Validate GW Exists on device

    Args:
        conn (Netmiko Connection Object)
        gw (str)

    Returns:
        True | False
    """
    """IMPORTANT NOTE -- this does not work very well!

    This will catch "1.1.1.1" even if the gw is "1.1.1.11" for example.
    Need to improve this!
    """
    command = f'show ip interface | i {gw}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'\t{output}')
    if str(gw) not in output:
        LOGGER.info(f'Gateway {gw} does NOT exist on device {conn.host}.')
        return(False)
    else:
        LOGGER.info(f'Gateway {gw} exists on device {conn.host}.')
        return(True)


def gw_gather_mask_from_ip(conn, gw):
    """Capture Subnet Mask for GW IP

    Args:
        conn (Netmiko Connection Object)
        gw (str)

    Returns:
        ip_addr
    """
    command = f'show ip interface | i {gw}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'\t{output}')
    cidr = re.search(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?', output).group()
    ip_addr = ipaddress.ip_interface(cidr)
    ip_addr = ip_addr.with_netmask.replace('/', ' ')
    return(ip_addr)


def gw_secondary(conn, gw):
    """Capture Subnet Mask for GW IP

    Args:
        conn (Netmiko Connection Object)
        gw (str)

    Returns:
        True | False
    """
    command = f'show ip interface | i {gw}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'{output}')
    if 'Secondary' in output:
        LOGGER.info(f'Gateway {gw} is secondary on device {conn.host}.')
        return(True)
    else:
        LOGGER.info(f'Gateway {gw} is NOT secondary on device {conn.host}.')
        return(False)


def gw_remove_ip(conn, vlan_interface, gw, secondary=False):
    """Remove IP from VLAN Interface

    Args:
        conn (Netmiko Connection Object)
        vl (int)
        gw (int)

    Returns:
        N/A
    """
    if secondary:
        commands = [f'interface {vlan_interface}',
                    f'no ip address {gw} secondary']
    else:
        commands = [f'interface {vlan_interface}',
                    f'no ip address {gw}']
    LOGGER.info(f'Sending configs "{commands}" to device {conn.host}.')
    try:
        conn.send_config_set(commands)
    except Exception as e:
        LOGGER.critical(f'Encountered an error removing IP address {gw} from '
                        f'interface {vlan_interface}. Error: {e}')
        continue_or_exit()


def find_interface_from_ip(conn, gw):
    """Capture Interface Name from GW IP

    Args:
        conn (Netmiko Connection Object)
        gw (str)

    Returns:
        vlan_interface (str) Name of VLAN interface; ex: Vlan110
    """
    command = f'show ip interface brief | i {gw}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'{output}')
    try:
        vlan_interface = re.search(r'^Vlan[1-4][0-9]{0,3}', output).group()
        return(vlan_interface)
    except AttributeError:
        LOGGER.info(f'It looks like gateway {gw} may be a secondary IP. '
                    'Continuing to search for parent interface...')

    command = 'show ip interface brief'
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'{output}')
    vlan_interfaces = re.findall(r'Vlan[1-4][0-9]{0,3}', output)
    for vlan in vlan_interfaces:
        command = f'show ip interface {vlan} | i {gw}'
        LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
        output = conn.send_command(command)
        LOGGER.info(f'Output from command "{command}" from device {conn.host}:'
                    f'\n{output}')
        vlan_interface = vlan
        if str(gw) in output:
            return(vlan_interface)


def vl_exists(conn, vlan_interface):
    """Validate GW Exists on device

    Args:
        conn (Netmiko Connection Object)
        vl (int)

    Returns:
        True | False
    """
    command = f'show ip interface {vlan_interface}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'{output}')
    if '% Invalid input detected' in output:
        LOGGER.info(f'VLAN {vlan_interface} does NOT exist on device '
                    f'{conn.host}.')
        return(False)
    else:
        LOGGER.info(f'VLAN {vlan_interface} exists on device {conn.host}.')
        return(True)


def vl_shut(conn, vlan_interface):
    """Shutdown VLAN Interface

    Args:
        conn (Netmiko Connection Object)
        vlan_interface (str) ex: Vlan110

    Returns:
        N/A
    """
    commands = [f'interface {vlan_interface}',
                'shutdown']
    LOGGER.info(f'Sending commands "{commands}" to device {conn.host}.')
    try:
        conn.send_config_set(commands)
    except Exception as e:
        LOGGER.critical(f'Encountered an error shutting down {vlan_interface}.'
                        f' Error: {e}')
        continue_or_exit()


def vl_ip(conn, vlan_interface):
    """Validate IP enabled on VLAN interface

    Args:
        conn (Netmiko Connection Object)
        vlan_interface (str)

    Returns:
        True | False
    """
    command = f'show ip interface {vlan_interface}'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    output = conn.send_command(command)
    LOGGER.info(f'Output from command "{command}" from device {conn.host}:\n'
                f'{output}')
    if 'Internet protocol processing disabled' in output:
        LOGGER.info(f'IP is DISABLED on interface {vlan_interface} on device '
                    f'{conn.host}.')
        return(False)
    else:
        LOGGER.info(f'IP is ENABLED on interface {vlan_interface} on device '
                    f' {conn.host}.')
        return(True)


def save_config(conn):
    """Save device configuration

    Args:
        conn (Netmiko Connection Object)

    Returns:
        N/A
    """
    command = 'copy running-config startup-config'
    LOGGER.info(f'Sending command "{command}" to device {conn.host}.')
    try:
        conn.send_command(command)
    except Exception as e:
        LOGGER.critical('Encountered the following error attempting to save '
                        f'configuration of {conn.host}. Error: {e}.')


def disconnect(conn):
    """Disconnect from device

    Args:
        conn (Netmiko Connection Object)

    Returns:
        N/A
    """
    try:
        LOGGER.info(f'Disconnecting from device {conn.host}.')
        conn.disconnect()
    except Exception as e:
        LOGGER.critical('Encountered the following error disconnecting  '
                        f'from device {conn.host}. Error: {e}.')


def remove_gw(conn, gw):
    """Remove GW from device

    Args:
        conn (Netmiko Connection Object)
        gw (str)

    Returns:
        N/A
    """
    ip = gw_gather_mask_from_ip(conn, gw)
    vlan_interface = find_interface_from_ip(conn, gw)
    secondary = gw_secondary(conn, gw)
    gw_remove_ip(conn, vlan_interface, ip, secondary=secondary)
    vlan_ip_enabled = vl_ip(conn, vlan_interface)
    if vlan_ip_enabled is False:
        vl_shut(conn, vlan_interface)


def aci_bd_enable_unicast(fablogin, tn_name, bd_name):
    """Enable Unicast Routing on ACI Bridge Domain

    Args:
        fablogin (acipdt fabric login object)
        tn_name (str) name of tenant in ACI
        bd_name (str) name of bridge domain in ACI

    Returns:
        N/A
    """
    payload = f'''
{{
    "fvBD": {{
        "attributes": {{
            "dn": "uni/tn-{tn_name}/BD-{bd_name}",
            "unicastRoute": "yes",
            "status": "modified"
        }}
    }}
}}
    '''
    uri = f'mo/uni/tn-{tn_name}/BD-{bd_name}'
    LOGGER.info(f'Sending the following payload to ACI at URI {uri}:\n'
                f'{payload}')
    status = acipdt.post(fablogin.apic, payload, fablogin.cookies, uri)
    LOGGER.info(f'ACI returned the following status: {status}.')
    if status != 200:
        LOGGER.critical('Error could not set unicast routing on Bridge Domain '
                        f'{bd_name}. Continue, but there may be issues...')


def aci_bd_add_subnet(fablogin, tn_name, bd_name, subnet, scope='private'):
    """Configure Subnet on ACI Bridge Domain

    Args:
        fablogin (acipdt fabric login object)
        tn_name (str) name of tenant in ACI
        bd_name (str) name of bridge domain in ACI
        subnet (str) cidr notation of subnet, ex: 1.1.1.1/24
        scope (str) (optional) public | private | shared | public,shared

    Returns:
        N/A
    """
    payload = f'''
{{
    "fvSubnet": {{
        "attributes": {{
            "dn": "uni/tn-{tn_name}/BD-{bd_name}/subnet-[{subnet}]",
            "ip": "{subnet}",
            "preferred": "no",
            "scope": "{scope}",
            "status": "created"
        }}
    }}
}}
    '''
    uri = f'mo/uni/tn-{tn_name}/BD-{bd_name}/subnet-[{subnet}]'
    LOGGER.info(f'Sending the following payload to ACI at URI {uri}:\n'
                f'{payload}')
    status = acipdt.post(fablogin.apic, payload, fablogin.cookies, uri)
    LOGGER.info(f'ACI returned the following status: {status}.')
    if status != 200:
        LOGGER.critical('Error could not deploy subnet on the Bridge Domain '
                        f'{bd_name}. Continuing, but there may be issues...')


def aci_snapshot_exist(fablogin, snapshot_file_name):
    """Check if ACI Snapshot exists

    Args:
        fablogin (acipdt fabric login object)
        snapshot_file_name (str) name of snapshot in aci
            ACI will append datetime info so this should be the 'base' filename

    Returns:
        snapshot_dns (list) dns of snapshots containing snapshot_file_name
            This list is ordered most recent to oldest
    """
    query = acipdt.Query(fablogin.apic, fablogin.cookies)
    query_string = 'configSnapshot'
    query_result = query.query_class(query_string)[1]['imdata']
    snap = [snap for snap in query_result if snapshot_file_name in
            snap['configSnapshot']['attributes']['fileName']]
    if snap:
        snapshot_dns = sorted(snap, key=lambda k:
                              k['configSnapshot']['attributes']['modTs'],
                              reverse=True)
        snapshot_dns = [snap['configSnapshot']['attributes']['dn'] for
                        snap in snapshot_dns]
        return(snapshot_dns)
    else:
        return(None)


def aci_snapshot_policy(fablogin, snapshot_file_name, status='created'):
    """Take or Delete ACI Snapshot

    Args:
        fablogin (acipdt fabric login object)
        snapshot_file_name (str) name of snapshot in aci
            ACI will append datetime info so this should be the 'base' filename

    Kwargs:
        status (str) (optional) created | modified | created,modified | deleted

    Returns:
        True if status == 200
        False if other
    """
    snapshot_args = {}
    snapshot_args['name'] = snapshot_file_name
    snapshot_args['snapshot'] = 'true'
    snapshot_args['status'] = status
    cfgmgmt = acipdt.FabCfgMgmt(fablogin.apic, fablogin.cookies)
    status = cfgmgmt.backup(**snapshot_args)
    if status == 200:
        return(True)
    else:
        return(False)


def aci_retire_snapshot(fablogin, snapshot_dn):
    """Retire (delete) a snapshot

    Args:
        fablogin (acipdt fabric login object)
        snapshot_dn (str) distinguished name of snapshot to retire

    Returns:
        True if status == 200
        False if other
    """
    payload = f'''
{{
    "configSnapshot": {{
        "attributes": {{
            "dn": "{snapshot_dn}",
            "retire": "true"
        }}
    }}
}}
    '''
    uri = f'mo/{snapshot_dn}'
    LOGGER.info(f'Sending the following payload to ACI at URI {uri}:\n'
                f'{payload}')
    status = acipdt.post(fablogin.apic, payload, fablogin.cookies, uri)
    LOGGER.info(f'ACI returned the following status: {status}.')
    if status == 200:
        return(True)
    else:
        LOGGER.critical('Failed to delete snapshot. Continuing.')
        return(False)


def aci_snapshot_rollback(fablogin, snapshot_dn):
    """Rollback to an ACI Snapshot

    Args:
        fablogin (acipdt fabric login object)
        snapshot_dn (str) distinguished name of snapshot to rollback to

    Returns:
        True if status == 200
        False if other
    """
    query = acipdt.Query(fablogin.apic, fablogin.cookies)
    snapshot_filename = query.query_dn(snapshot_dn)[1]['imdata'][0]['configSnapshot']['attributes']['fileName']
    cfgmgmt = acipdt.FabCfgMgmt(fablogin.apic, fablogin.cookies)
    snapshot_args = {}
    snapshot_args['name'] = snapshot_filename
    status = cfgmgmt.snapback(**snapshot_args)
    if status == 200:
        return(True)
    else:
        return(False)


def migrate_gw(dev, gw, username, password, fablogin):
    """Migrate gateway from legacy device to ACI

    Args:
        dev (tuple); (netmiko device type, device ip)
        gw (dict); dictionary containing information about gateway
            Gateway IP, Subnet Mask, Tenant, Application Profile, EPG, BD
        username (str); username for legacy device(s)
        password (str); password for legacy device(s)
        fablogin (acipdt fab login object)

    Returns:
        N/A
    """
    conn = connect(username, password, dev[0], dev[1])
    remove_gw(conn, gw['Gateway'])
    disconnect(conn)
    aci_bd_enable_unicast(fablogin, gw['Tenant'], gw['BD'])
    aci_bd_add_subnet(fablogin, gw['Tenant'], gw['BD'],
                      f'{gw["Gateway"]}{gw["SubnetMask"]}')



def main():
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Migrate gateways to ACI!')

    # Optional Username args
    parser.add_argument('-u', type=str, nargs='?',
                        help='Username to connect to network devices.')
    parser.add_argument('-aciu', type=str, nargs='?',
                        help='Username to connect to ACI.')

    # Gateway argument (required if not passing in file)
    parser.add_argument('-gw', type=ipaddress.ip_address, nargs='?',
                        help='Gateway you would like to migrate.')

    # TN and BD arguments (required if not passing in file)
    parser.add_argument('-tn', type=str, nargs='?',
                        help='Tenant in which gateway lives.')
    parser.add_argument('-bd', type=str, nargs='?',
                        help='Bridge Domain on which gateway lives.')

    # File argument
    parser.add_argument('-f', default=None, nargs='?',
                        help='CSV file containing gateways to migrate.')

    # Optional noconfirm argument -- default will prompt for confirmation
    parser.add_argument('-noconfirm', action='store_true',
                        help='Do NOT confirm before making changes.')

    # Optional Args (mask, app profile, epg)
    parser.add_argument('-mask', type=str, nargs='?',
                        help='Subnet mask as CIDR or dotted decimal.')
    parser.add_argument('-ap', type=str, nargs='?',
                        help='Application Profile associated EPG resides in.')
    parser.add_argument('-epg', type=str, nargs='?',
                        help='Subnet mask as CIDR or dotted decimal.')

    args = parser.parse_args()

    LOGGER.info(f'Script initiated with the following arguments:\n\t{args}')

    if args.f and (args.gw or args.tn or args.bd):
        LOGGER.critical('File in and (gw|tn|bd) are mutually exclusive. '
                        'Exiting.')
        raise parser.error('File in and (gw|tn|bd) are mutually exclusive.')
    elif args.f:
        try:
            df = pandas.read_csv(args.f)
            if not CSV_COLUMNS == list(df.columns.values):
                LOGGER.critical('CSV columns do not match expected input. '
                                f'Columns should be: {CSV_COLUMNS}, Received" '
                                f'{list(df.columns.values)}. Exiting.')
                sys.exit(1)
        except Exception as e:
            LOGGER.critical('Failed to load CSV to data frame, exiting.'
                            f'Error: {e}')
            sys.exit(1)
    elif None in (args.gw, args.tn, args.bd):
        LOGGER.critical('If passing gw, must also pass tn and bd arguments.')
        raise parser.error('Insufficient required arguments.')

    # Parse username arg or use statically set values
    if not args.u and USERNAME:
        LOGGER.info('No username provided at execution, using static value in '
                    f'script: {USERNAME}.')
        args.u = USERNAME
    else:
        LOGGER.critical('No username provided at execution or in script. '
                        'Exiting.')
        sys.exit(1)

    # Parse username arg or use statically set values
    if not args.aciu and ACI_USERNAME:
        LOGGER.info('No ACI username provided at execution, using static value'
                    f' in script: {ACI_USERNAME}.')
        args.aciu = ACI_USERNAME
    else:
        LOGGER.critical('No ACI username provided at execution or in script. '
                        'Exiting.')
        sys.exit(1)

    # Prompt user for device password or use statically set values
    if PASSWORD:
        LOGGER.info('Password defined in script, using that value.')
        password = PASSWORD
    else:
        LOGGER.info('No password defined in script, prompting user.')
        password = getpass.getpass('Enter your device password: ')

    # Prompt user for device password or use statically set values
    if ACI_PASSWORD:
        LOGGER.info('ACI password defined in script, using that value.')
        aci_password = ACI_PASSWORD
    else:
        LOGGER.info('No ACI password defined in script, prompting user.')
        aci_password = getpass.getpass('Enter your device password: ')

    # Create list of conn objects for each legacy device
    conns = []
    for dev in LEGACY_DEVICES:
        if dev[0] == 'cisco_ios':
            conns.append(connect(args.u, password, dev[0], dev[1]))

    # Validate ACI Connectivity, create login object
    try:
        fablogin = acipdt.FabLogin(ACI_HOST, args.aciu, aci_password)
        fablogin.login()
    except Exception as e:
        LOGGER.critical(f'Error logging into ACI. Error: {e}. Exiting.')
        sys.exit(1)

    # If not passing in a file, load the df from arguments
    if not args.f:
        df = pandas.DataFrame(columns=CSV_COLUMNS,
                              data=[[args.gw, args.mask, args.tn, args.ap,
                                    args.epg, args.bd]])

    # Create a list of all gw to move, ensuring gw exists on all legacy devices
    gw_moves = []
    for row in df.iterrows():
        row = row[1].to_dict()
        for dev in conns:
            if gw_exists(dev, row['Gateway']):
                gw_moves.append(row)
            else:
                LOGGER.critical(f'Gateway ip {row["Gateway"]} does not exist on  '
                                f'device {dev.host}. This gateway will be removed'
                                ' from the  migration list if you chose to '
                                'continue.')
                continue_or_exit()

    # Disconnect previous connections as we will be re-connecting to each
    # device in the 'process_gw' function -- this allows us to have multiple
    # sessions open at one time to each device
    for dev in conns:
        disconnect(dev)

    # If SNAPSHOT set to TRUE, check if exists, delete if needed
    # and take a new one
    if SNAPSHOT:
        snapshot_dns = aci_snapshot_exist(fablogin, SNAPSHOT_FILE_NAME)
        if snapshot_dns:
            LOGGER.info(f'Multiple snapshots containing {SNAPSHOT_FILE_NAME} '
                        f'exist:\n{snapshot_dns}')
            msg = (f'Snapshot(s) exist containing "{SNAPSHOT_FILE_NAME}"; '
                   'do you want to continue?')
            continue_or_exit(msg=msg)
            # Should I delete the old snaps here?
        # Create policy and take snapshot; sleep to ensure snapshot is taken
        # before deleting policy
        aci_snapshot_policy(fablogin, SNAPSHOT_FILE_NAME)
        time.sleep(2)
        # Clean up aci_gw_migrator snapshot policy
        aci_snapshot_policy(fablogin, SNAPSHOT_FILE_NAME, status='deleted')

    # Create up to MAX_CONNS processes to move gateways
    for dev in LEGACY_DEVICES:
        with Pool(processes=MAX_CONNS) as p:
            for gw in gw_moves:
                p.apply_async(migrate_gw, args=(dev, gw, args.u,
                                                password, fablogin))
            p.close()
            p.join()

    # If SNAPSHOT set to TRUE offer rollback or delete snapshot
    if SNAPSHOT:
        msg = ('Migration complete, if you chose to continue you can '
               'rollback or delete the snapshot.')
        continue_or_exit(msg=msg)
        while True:
            user_input = input("If you would like you can rollback [r] to the"
                               " previous snapshot, delete [d] the previous "
                               "snapshot or exit [exit] the script. What would"
                               " you like to do? 'r', 'd' or 'exit' [exit]: ")
            selection = user_input or 'exit'
            if selection.lower() == 'exit':
                LOGGER.debug('User decided to exit. Exiting.')
                sys.exit(0)
            elif selection.lower() == 'r':
                LOGGER.debug('User decided to rollback ACI.')
                snapshot_dns = aci_snapshot_exist(fablogin, SNAPSHOT_FILE_NAME)
                aci_snapshot_rollback(fablogin, snapshot_dns[0])
                sys.exit(0)
            elif selection.lower() == 'd':
                LOGGER.debug('User decided to delete ACI snapshot.')
                snapshot_dns = aci_snapshot_exist(fablogin, SNAPSHOT_FILE_NAME)
                aci_retire_snapshot(fablogin, snapshot_dns[0])
                sys.exit(0)


if __name__ == '__main__':
    main()
