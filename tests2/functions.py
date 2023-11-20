from ipaddress import ip_interface
from secrets import choice
from shutil import which
from string import ascii_uppercase, digits
from subprocess import run, Popen, PIPE, TimeoutExpired

__all__ = [
    'run_ssh_cmd',
    'complete_ssh_cmd',
    'scp_file',
    'determine_vip',
]


def determine_vip(ipinfo):
    # TODO: assumes version 4 only
    for i in ip_interface(ipinfo).network:
        last_octet = int(i.compressed.split('.')[-1])
        if last_octet < 15 or last_octet >= 250:
            # addresses like *.255, *.0 and any of them that
            # are < *.15 we'll ignore. Those are typically
            # reserved for routing/switch devices anyways
            continue
        elif run(['ping', '-c', '2', '-w', '4', i.compressed]).returncode != 0:
            # sent 2 packets to the address and got no response so assume
            # it's safe to use
            return i.compressed


def random_hostname(is_ha, domain=True):
    # NOTE: the keys in this dictionary match the network.global.update
    # endpoint. We do this so the caller of this method doesnt have to
    # do a bunch of manipulation based on whether or not its HA system
    info = {'hostname': ''}
    if not is_ha:
        info['hostname'] = f'test{"".join(choice((ascii_uppercase + digits)) for i in range(10))}'
        if domain:
            info['domain'] = f'{info["hostname"]}.nb.ixsystems.com'
    else:
        host = f'ha{"".join(choice((ascii_uppercase + digits)) for i in range(9))}'
        info['hostname'] = f'{host}-c1'
        info['hostname_b'] = f'{host}-c2'
        info['hostname_virtual'] = f'{host}-v'
        if domain:
            info['domain'] = f'{info["hostname_virtual"]}.nb.ixsystems.com'

    return info


def build_base_cmd(password, host, scp=False):
    return [
        which('sshpass'), '-p', password,
        which('ssh') if not scp else which('scp'),
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'VerifyHostKeyDNS=no',
    ]


def build_ssh_cmd(command, username, password, host):
    cmd = build_base_cmd(password, host)
    cmd.extend([f'{username}@{host}', command])
    return cmd


def scp_file(file, destination, username, password, host, get=True):
    cmd = build_base_cmd(password, host, scp=True)
    if get:
        cmd.extend([file, f'{username}@{host}:{destination}'])
    else:
        cmd.extend([f'{username}@{host}:{file}', destination])


def run_ssh_cmd(command, username, password, host, timeout=120, async_=False):
    cmd = build_ssh_cmd(command, username, password, host)
    popen_opts = {'stdout': PIPE, 'stderr': PIPE, 'universal_newlines': True}
    if async_:
        return Popen(cmd, **popen_opts)
    else:
        with Popen(cmd, **popen_opts) as proc:
            return complete_ssh_cmd(proc, timeout=timeout)


def complete_ssh_cmd(proc, timeout=120):
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    stdout = stdout.strip()
    stderr = stderr.strip()
    error = None
    rc = proc.returncode
    if rc != 0:
        if stderr:
            error = stderr
        elif stdout:
            error = stdout
        else:
            error = 'NO ERROR MESSAGE'

    return {
        'stdout': stdout,
        'stderr': stderr,
        'returncode': rc,
        'error': error,
        'success': rc == 0,
    }
