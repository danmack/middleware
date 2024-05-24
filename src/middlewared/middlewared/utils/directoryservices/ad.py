import errno
import json
import subprocess

from .ad_constants import (
    ADUserAccountControl,
    ADEncryptionTypes
)
from middlewared.plugins.smb_.constants import SMBCmd
from middlewared.service_exception import CallError
from typing import Optional


def get_domain_info(domain: str) -> dict:
    """
    Use libads to query information about the specified domain.

    Returned dictionary contains following info:

    `ldap_server` IP address of current LDAP server to which TrueNAS is connected.

    `ldap_server_name` DNS name of LDAP server to which TrueNAS is connected

    `realm` Kerberos realm

    `ldap_port`

    `server_time` timestamp.

    `kdc_server` Kerberos KDC to which TrueNAS is connected

    `server_time_offset` current time offset from DC.

    `last_machine_account_password_change`. timestamp
    """
    netads = subprocess.run([
        SMBCmd.NET.value,
        '-S', domain,
        '--json',
        '--option', f'realm={domain}',
        'ads', 'info'
    ], check=False, capture_output=True)

    if netads.returncode == 0:
        data = json.loads(netads.stdout.decode())

        # normalize keys for our output
        for key in list(data.keys()):
            value = data.pop(key)
            new_key = '_'.join(key.split()).lower()
            data[new_key] = value

        return data

    if (err_msg := netads.stderr.decode().strip()) == "Didn't find the ldap server!":
        raise CallError(
            'Failed to discover Active Directory Domain Controller '
            'for domain. This may indicate a DNS misconfiguration.',
            errno.ENOENT
        )

    raise CallError(err_msg)


def get_machine_account_status(target_dc: Optional[str] = None) -> dict:
    def parse_result(data, out):
        if ':' not in data:
            return

        key, value = data.split(':', 1)
        if key not in out:
            # This is not a line we're interested in
            return

        if type(out[key]) == list:
            out[key].append(value.strip())
        elif out[key] == -1:
            out[key] = int(value.strip())
        else:
            out[key] = value.strip()

        return

    cmd = [SMBCmd.NET.value, '-P', 'ads', 'status']
    if target_dc:
        cmd.extend(['-S', target_dc])

    results = subprocess.run(cmd, capture_output=True)
    if results.returncode != 0:
        raise CallError(
            'Failed to retrieve machine account status: '
            f'{results.stderr.decode().strip()}'
        )

    output = {
        'userAccountControl': -1,
        'objectSid': None,
        'sAMAccountName': None,
        'dNSHostName': None,
        'servicePrincipalName': [],
        'msDS-SupportedEncryptionTypes': -1
    }

    for line in results.stdout.decode().splitlines():
        parse_result(line, output)

    output['userAccountControl'] = ADUserAccountControl.parse_flags(output['userAccountControl'])
    output['msDS-SupportedEncryptionTypes'] = ADEncryptionTypes.parse_flags(output['msDS-SupportedEncryptionTypes'])
    return output
