#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD
# Location for tests into REST API of FreeNAS

import ipaddress
import os
from copy import copy
from time import sleep

import pytest
from middlewared.service_exception import ValidationError, ValidationErrors, CallError
from middlewared.test.integration.assets.account import group as create_group
from middlewared.test.integration.assets.account import user as create_user
from middlewared.test.integration.assets.filesystem import directory
from middlewared.test.integration.assets.nfs import (
    nfs_config, nfs_share_config, query_nfs_service
)
from middlewared.test.integration.assets.pool import dataset as nfs_dataset
from middlewared.test.integration.utils import call, mock, ssh
from middlewared.test.integration.utils.client import truenas_server
from middlewared.test.integration.utils.system import \
    reset_systemd_svcs as reset_svcs

from auto_config import hostname, password, pool_name, user
from protocols import SSH_NFS, nfs_share


MOUNTPOINT = f"/tmp/nfs-{hostname}"
nfs_dataset_name = f"{pool_name}/nfs"
NFS_PATH = "/mnt/" + nfs_dataset_name

# Supported configuration files
conf_file = {
    "nfs": {
        "pname": "/etc/nfs.conf.d/local.conf",
        "sections": {
            'nfsd': {},
            'exportd': {},
            'nfsdcld': {},
            'nfsdcltrack': {},
            'mountd': {},
            'statd': {},
            'lockd': {}}
    },
    "idmapd": {
        "pname": "/etc/idmapd.conf",
        "sections": {"General": {}, "Mapping": {}, "Translation": {}}
    }
}


# =====================================================================
#                     Fixtures and utilities
# =====================================================================

def parse_exports():
    results = ssh("cat /etc/exports")
    exp = results.splitlines()
    rv = []
    for idx, line in enumerate(exp):
        if not line or line.startswith('\t'):
            continue

        entry = {"path": line.strip()[1:-2], "opts": []}

        i = idx + 1
        while i < len(exp):
            if not exp[i].startswith('\t'):
                break

            e = exp[i].strip()
            host, params = e.split('(', 1)
            entry['opts'].append({
                "host": host,
                "parameters": params[:-1].split(",")
            })
            i += 1

        rv.append(entry)

    return rv


def parse_server_config(conf_type="nfs"):
    '''
    Parse known 'ini' style conf files.  See definition of conf_file above.

    Debian will read to /etc/default/nfs-common and then /etc/nfs.conf
    All TrueNAS NFS settings are in /etc/nfs.conf.d/local.conf as overrides
    '''
    assert conf_type in conf_file.keys(), f"{conf_type} is not a supported conf type"
    pathname = conf_file[conf_type]['pname']
    rv = conf_file[conf_type]['sections']
    expected_sections = rv.keys()

    # Read the file and parse it
    res = ssh(f"cat {pathname}")
    conf = res.splitlines()
    section = ''

    for line in conf:
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.split('[')[1].split(']')[0]
            assert section in expected_sections, f"Unexpected section found: {section}"
            continue

        k, v = line.split(" = ", 1)
        rv[section].update({k: v})

    return rv


def parse_rpcbind_config():
    '''
    In Debian 12 (Bookwork) rpcbind uses /etc/default/rpcbind.
    Look for /etc/rpcbind.conf in future releases.
    '''
    results = ssh("cat /etc/default/rpcbind")
    conf = results.splitlines()
    rv = {}

    # With bindip the line of intrest looks like: OPTIONS=-w -h 192.168.40.156
    for line in conf:
        if not line or line.startswith("#"):
            continue
        if line.startswith("OPTIONS"):
            opts = line.split('=')[1].split()
            # '-w' is hard-wired, lets confirm that
            assert len(opts) > 0
            assert '-w' == opts[0]
            rv['-w'] = ''
            # If there are more opts they must the bindip settings
            if len(opts) == 3:
                rv[opts[1]] = opts[2]

    return rv


def get_nfs_service_state():
    """ Return nfs 'state' value from service.query """
    service_state = call('service.query', [['service', '=', 'nfs']], {'get': True})
    return service_state['state']


def set_nfs_service_state(do_what=None, expect_to_pass=True, fail_check=None):
    """
    Start or Stop NFS service
    expect_to_pass parameter is optional
    fail_check parameter is optional
    NOTE: 'test_files_in_exportsd' uses the optional parameters
    """
    assert do_what in ['start', 'stop'], f"Requested invalid service state: {do_what}"
    test_res = {'start': True, 'stop': False}

    if expect_to_pass:
        res = call(f'service.{do_what}', 'nfs', {'silent': False})
        sleep(1)
        return res
    else:
        with pytest.raises(CallError) as e:
            call(f'service.{do_what}', 'nfs', {'silent': False})
        if fail_check:
            assert fail_check in str(e.value)

    # Confirm requested state
    if expect_to_pass:
        res = call('service.started', 'nfs')
        assert res == test_res[do_what], f"Expected {test_res[do_what]} for NFS started result, but found {res}"
        return res


def confirm_nfsd_processes(expected):
    '''
    Confirm the expected number of nfsd processes are running
    '''
    result = ssh("cat /proc/fs/nfsd/threads")
    assert int(result) == expected, result


def confirm_mountd_processes(expected):
    '''
    Confirm the expected number of mountd processes are running
    '''
    rx_mountd = r"rpc\.mountd"
    result = ssh(f"ps -ef | grep '{rx_mountd}' | wc -l")

    # If there is more than one, we subtract one to account for the rpc.mountd thread manager
    num_detected = int(result)
    assert (num_detected - 1 if num_detected > 1 else num_detected) == expected


def confirm_rpc_processes(expected=['idmapd', 'bind', 'statd']):
    '''
    Confirm the expected rpc processes are running
    NB: This only supports the listed names
    '''
    prepend = {'idmapd': 'rpc.', 'bind': 'rpc', 'statd': 'rpc.'}
    for n in expected:
        procname = prepend[n] + n
        result = ssh(f"pgrep {procname}")
        assert len(result.splitlines()) > 0


def confirm_nfs_version(expected=[]):
    '''
    Confirm the expected NFS versions are 'enabled and supported'
    Possible values for expected:
        ["3"] means NFSv3 only
        ["4"] means NFSv4 only
        ["3","4"] means both NFSv3 and NFSv4
    '''
    results = ssh("rpcinfo -s | grep ' nfs '")
    for v in expected:
        assert v in results.strip().split()[1], results


def confirm_rpc_port(rpc_name, port_num):
    '''
    Confirm the expected port for the requested rpc process
    rpc_name = ('mountd', 'status', 'nlockmgr')
    '''
    line = ssh(f"rpcinfo -p | grep {rpc_name} | grep tcp")
    # example:    '100005    3   tcp    618  mountd'
    assert int(line.split()[3]) == port_num, str(line)


class NFS_CONFIG:
    '''
    This is used to restore the NFS config to it's original state
    '''
    initial_nfs_config = {}

    # These are the expected default config values
    default_config = {
        "allow_nonroot": False,
        "protocols": ["NFSV3", "NFSV4"],
        "v4_v3owner": False,
        "v4_krb": False,
        "v4_domain": "",
        "bindip": [],
        "mountd_port": None,
        "rpcstatd_port": None,
        "rpclockd_port": None,
        "mountd_log": False,  # nfs.py indicates this should be True, but db says False
        "statd_lockd_log": False,
        "v4_krb_enabled": False,
        "userd_manage_gids": False,
        "keytab_has_nfs_spn": False,
        "managed_nfsd": True
    }

    initial_service_state = {}

    # These are the expected default run state values
    default_service_state = {
        "service": "nfs",
        "enable": False,
        "state": "STOPPED",
        "pids": []
    }


@pytest.fixture(scope="module")
def init_nfs():
    """ Will restore to _default_ config and state at module exit """
    try:
        initial_config = call("nfs.config")
        NFS_CONFIG.initial_nfs_config = copy(initial_config)

        # initial_service_state = call('service.query', [['service', '=', 'nfs']], {'get': True})
        initial_service_state = query_nfs_service()
        NFS_CONFIG.initial_service_state = copy(initial_service_state)

        yield {"config": initial_config, "service_state": initial_service_state}
    finally:
        # Restore to -default- state  (some might be redundant, but ensures clean state at exit)
        call('service.update', 'nfs', {'enable': NFS_CONFIG.default_service_state['enable']})
        state_cmd = {'RUNNING': 'start', 'STOPPED': 'stop'}
        set_nfs_service_state(state_cmd[NFS_CONFIG.default_service_state['state']])

        # Restore to -default- config
        exclude = ['servers', 'v4_krb_enabled', 'v4_owner_major', 'keytab_has_nfs_spn', 'managed_nfsd']
        default_config_payload = {k: v for k, v in NFS_CONFIG.default_config.items() if k not in exclude}
        if NFS_CONFIG.default_config['managed_nfsd']:
            default_config_payload['servers'] = None
        call('nfs.update', default_config_payload)


@pytest.fixture(scope="module")
def nfs_dataset_and_share():
    """ Will delete the 'nfs' share and dataset at the module exit """
    with nfs_dataset('nfs') as ds:
        with nfs_share(NFS_PATH, {
                "comment": "My Test Share",
                "security": ["SYS"]
        }) as nfsid:
            yield {"nfsid": nfsid, "ds": ds}


@pytest.fixture(scope="class")
def start_nfs():
    """ The exit state is managed by init_nfs """
    try:
        yield set_nfs_service_state('start')
    finally:
        print("[MCG DEBUG] stop nfs")
        set_nfs_service_state('stop')


# =====================================================================
#                           Tests
# =====================================================================

def test_config(init_nfs):
    initial_config = init_nfs['config']
    initial_service_state = init_nfs['service_state']

    # We should be starting with the default config
    # Check the hard way so that we can identify the culprit
    for k, v in NFS_CONFIG.default_config.items():
        assert initial_config.get(k) == v, f'Expected {k}:"{v}", but found {k}:"{initial_config.get(k)}"'

    # Confirm NFS is not running
    assert initial_service_state['state'] == 'STOPPED', \
        f"Before update, expected STOPPED, but found {initial_service_state['state']}"


def test_service_enable_at_boot(init_nfs):
    initial_run_state = init_nfs['service_state']
    assert initial_run_state['enable'] is False

    svc_id = call('service.update', 'nfs', {"enable": True})
    nfs_state = call('service.query', [["id", "=", svc_id]])
    assert nfs_state[0]['service'] == "nfs"
    assert nfs_state[0]['enable'] is True


def test_dataset_permissions(nfs_dataset_and_share):
    ds = nfs_dataset_and_share["ds"]
    call('pool.dataset.permission', ds, {
        "acl": [],
        "mode": "777",
        "user": "root",
        "group": 'root'
    }, job=True)


class TestNFSops:
    """
    Most of the tests are in this class where the server is running
    """
    def test_state_directory(self, start_nfs):
        """
        By default, the NFS state directory is at /var/lib/nfs.
        To support HA systems, we moved this to the system dataset
        at /var/db/system/nfs.  In support of this we updated the
        NFS conf file settings
        """
        assert start_nfs is True

        # Make sure the conf file has the expected settings
        nfs_state_dir = '/var/db/system/nfs'
        s = parse_server_config()
        assert s['exportd']['state-directory-path'] == nfs_state_dir, str(s)
        assert s['nfsdcld']['storagedir'] == os.path.join(nfs_state_dir, 'nfsdcld'), str(s)
        assert s['nfsdcltrack']['storagedir'] == os.path.join(nfs_state_dir, 'nfsdcltrack'), str(s)
        assert s['nfsdcld']['storagedir'] == os.path.join(nfs_state_dir, 'nfsdcld'), str(s)
        assert s['mountd']['state-directory-path'] == nfs_state_dir, str(s)
        assert s['statd']['state-directory-path'] == nfs_state_dir, str(s)
        # Confirm we have the mount point in the system dataset
        # ----------------------------------------------------------------------
        # NOTE: Update test_001_ssh.py: test_002_first_boot_checks.
        # NOTE: Test fresh-install and upgrade.
        # ----------------------------------------------------------------------

    @pytest.mark.parametrize('vers', [3, 4])
    def test_basic_nfs_ops(self, start_nfs, nfs_dataset_and_share, vers):
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        with SSH_NFS(truenas_server.ip, NFS_PATH, vers=vers, user=user,
                     password=password, ip=truenas_server.ip) as n:
            n.create('testfile')
            n.mkdir('testdir')
            contents = n.ls('.')
            assert 'testdir' in contents
            assert 'testfile' in contents

            n.unlink('testfile')
            n.rmdir('testdir')
            contents = n.ls('.')
            assert 'testdir' not in contents
            assert 'testfile' not in contents

    def test_server_side_copy(self, start_nfs, nfs_dataset_and_share):
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user,
                     password=password, ip=truenas_server.ip) as n:
            n.server_side_copy('ssc1', 'ssc2')

    @pytest.mark.parametrize('nfsd,cores,expected', [
        (50, 1, {'nfsd': 50, 'mountd': 12, 'managed': False}),   # User specifies number of nfsd, expect: 50 nfsd, 12 mountd
        (None, 12, {'nfsd': 12, 'mountd': 3, 'managed': True}),  # Dynamic, expect 12 nfsd and 3 mountd
        (None, 4, {'nfsd': 4, 'mountd': 1, 'managed': True}),    # Dynamic, expect 4 nfsd and 1 mountd
        (None, 2, {'nfsd': 2, 'mountd': 1, 'managed': True}),    # Dynamic, expect 2 nfsd and 1 mountd
        (None, 1, {'nfsd': 1, 'mountd': 1, 'managed': True}),    # Dynamic, expect 1 nfsd and 1 mountd
        (0, 4, {'nfsd': 4, 'mountd': 1, 'managed': True}),       # Should be trapped by validator: Illegal input
        (257, 4, {'nfsd': 4, 'mountd': 1, 'managed': True}),     # Should be trapped by validator: Illegal input
        (None, 48, {'nfsd': 32, 'mountd': 8, 'managed': True}),  # Dynamic, max nfsd via calculation is 32
        (-1, 48, {'nfsd': 32, 'mountd': 8, 'managed': True}),    # -1 is a flag to set bindip and confirm 'managed' stays True
    ])
    def test_service_update(self, start_nfs, nfs_dataset_and_share, nfsd, cores, expected):
        """
        This test verifies that service can be updated in general,
        and also that the 'servers' key can be altered.
        Latter goal is achieved by reading the nfs config file
        and verifying that the value here was set correctly.

        Update:
        The default setting for 'servers' is None. This specifies that we dynamically
        determine the number of nfsd to start based on the capabilities of the system.
        In this state, we choose one nfsd for each CPU core.
        The user can override the dynamic calculation by specifying a
        number greater than zero.

        The number of mountd will be 1/4 the number of nfsd.
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        with mock("system.cpu_info", return_value={"core_count": cores}):

            # Use 0 as 'null' flag
            if nfsd is None or nfsd in range(1, 257):
                call("nfs.update", {"servers": nfsd})

                s = parse_server_config()
                assert int(s['nfsd']['threads']) == expected['nfsd'], str(s)
                assert int(s['mountd']['threads']) == expected['mountd'], str(s)

                confirm_nfsd_processes(expected['nfsd'])
                confirm_mountd_processes(expected['mountd'])
                confirm_rpc_processes()

                # In all passing cases, the 'servers' field represents the number of expected nfsd
                nfs_conf = call("nfs.config")
                assert nfs_conf['servers'] == expected['nfsd']
                assert nfs_conf['managed_nfsd'] == expected['managed']
            else:
                if nfsd == -1:
                    # We know apriori that the current state is managed_nfsd == True
                    with nfs_config():
                        # Test making change to non-'server' setting does not change managed_nfsd
                        call("nfs.update", {"bindip": [truenas_server.ip]})
                        assert call("nfs.config")['managed_nfsd'] == expected['managed']
                else:
                    with pytest.raises(ValidationErrors) as ve:
                        assert call("nfs.config")['managed_nfsd'] == expected['managed']
                        call("nfs.update", {"servers": nfsd})

                    assert ve.value.errors == [ValidationError('nfs_update.servers', 'Should be between 1 and 256', 22)]

    def test_share_update(self, start_nfs, nfs_dataset_and_share):
        """
        Test changing the security and enabled fields
        We want nfs running to allow confirmation of changes in exportfs
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']
        with nfs_share_config(nfsid) as share_data:
            assert share_data['security'] != []
            nfs_share = call('sharing.nfs.update', nfsid, {"security": [], "comment": "no comment"})

            # The default is 'SYS', so changing from ['SYS'] to [] does not change /etc/exports
            assert nfs_share['security'] == [], f"Expected [], but found {nfs_share[0]['security']}"
            assert nfs_share['comment'] == "no comment"

            # Confirm changes are reflected in /etc/exports
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            export_opts = parsed[0]['opts'][0]['parameters']
            assert "sec=sys" in export_opts

            # Test share disable
            assert share_data['enabled'] is True
            nfs_share = call('sharing.nfs.update', nfsid, {"enabled": False})
            assert parse_exports() == []

    @pytest.mark.parametrize("networklist,ExpectedToPass,FailureMsg", [
        # IPv4
        (["192.168.0.0/24", "192.168.1.0/24"], True, ""),       # Non overlap
        (["192.168.0.0/16", "192.168.1.0/24"], False, "Overlapped"),      # Ranges overlap
        (["192.168.0.0/24", "192.168.0.211/32"], False, "Overlapped"),    # Ranges overlap
        (["192.168.0.0/64"], False, "does not appear to be an IPv4 or IPv6 network"),    # Invalid range, "Invalid"
        (["bogus_network"], False, "does not appear to be an IPv4 or IPv6 network"),     # Invalid, "Invalid"
        (["192.168.27.211"], True, ""),     # Non-CIDR format, ""
        # IPv6
        (["2001:0db8:85a3:0000:0000:8a2e::/96", "2001:0db8:85a3:0000:0000:8a2f::/96"],
            True, ""),                  # Non overlap
        (["2001:0db8:85a3:0000:0000:8a2e::/96", "2001:0db8:85a3:0000:0000:8a2f::/88"],
            False, "Overlapped"),       # Ranges overlap
        (["2001:0db8:85a3:0000:0000:8a2e::/96", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"],
            False, "Overlapped"),       # Ranges overlap
        (["2001:0db8:85a3:0000:0000:8a2e:0370:7334/256"],
            False, "does not appear to be an IPv4 or IPv6 network"),  # Invalid range
        (["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
            True, ""),                  # Non-CIDR format
    ])
    def test_share_networks(
            self, start_nfs, nfs_dataset_and_share, networklist, ExpectedToPass, FailureMsg):
        """
        Verify that adding a network generates an appropriate line in exports
        file for same path. Sample:

        "/mnt/dozer/nfs"\
            192.168.0.0/24(sec=sys,rw,subtree_check)\
            192.168.1.0/24(sec=sys,rw,subtree_check)
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']

        with nfs_share_config(nfsid):
            if ExpectedToPass:
                call('sharing.nfs.update', nfsid, {'networks': networklist})
            else:
                with pytest.raises(ValidationErrors) as re:
                    call('sharing.nfs.update', nfsid, {'networks': networklist})
                assert FailureMsg in str(re.value.errors[0])

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)

            exports_networks = [x['host'] for x in parsed[0]['opts']]
            if ExpectedToPass:
                # The input is converted to CIDR format which often will
                # look different from the input. e.g. 1.2.3.4/16 -> 1.2.0.0/16
                cidr_list = [str(ipaddress.ip_network(x, strict=False)) for x in networklist]
                # The entry should be present
                diff = set(cidr_list) ^ set(exports_networks)
                assert len(diff) == 0, f'diff: {diff}, exports: {parsed}'
            else:
                # The entry should not be present
                assert len(exports_networks) == 1, str(parsed)

    @pytest.mark.parametrize("hostlist,ExpectedToPass,FailureMsg", [
        # Valid hostnames (IP addresses) and netgroup
        (["192.168.0.69", "192.168.0.70", "@fakenetgroup"], True, ""),
        # Valid wildcarded hostnames
        (["asdfnm-*", "?-asdfnm-*", "asdfnm[0-9]", "nmix?-*dev[0-9]"], True, ""),
        # Valid wildcarded hostname with valid 'domains'
        (["asdfdm-*.example.com", "?-asdfdm-*.ixsystems.com",
          "asdfdm[0-9].example.com", "dmix?-*dev[0-9].ixsystems.com"], True, ""),
        # Invalid hostnames
        (["-asdffail", "*.asdffail.com", "*.*.com", "bozofail.?.*"], False, "Unable to resolve"),
        (["bogus/name"], False, "Unable to resolve"),
        (["192.168.1.0/24"], False, "Unable to resolve"),
        # Mix of valid and invalid hostnames
        (["asdfdm[0-9].example.com", "-asdffail",
          "devteam-*.ixsystems.com", "*.asdffail.com"], False, "Unable to resolve"),
        # Duplicate names (not allowed)
        (["192.168.1.0", "192.168.1.0"], False, "not unique"),
        (["ixsystems.com", "ixsystems.com"], False, "not unique"),
        # Mixing 'everybody' and named host
        (["ixsystems.com", "*"], False, "everybody"),    # Test NAS-123042, export collision, same path and entry
        (["*", "*.ixsystems.com"], False, "everybody"),  # Test NAS-123042, export collision, same path and entry
        # Invalid IP address
        (["192.168.1.o"], False, "Unable to resolve"),
        # Hostname with spaces
        (["bad host"], False, "cannot contain spaces"),
        # IPv6
        (["2001:0db8:85a3:0000:0000:8a2e:0370:7334"], True, "")
    ])
    def test_share_hosts(
            self, start_nfs, nfs_dataset_and_share, hostlist, ExpectedToPass, FailureMsg):
        """
        Verify that adding a network generates an appropriate line in exports
        file for same path. Sample:

        "/mnt/dozer/nfs"\
            192.168.0.69(sec=sys,rw,subtree_check)\
            192.168.0.70(sec=sys,rw,subtree_check)\
            @fakenetgroup(sec=sys,rw,subtree_check)

        host name handling in middleware:
            If the host name contains no wildcard or special chars,
                then we test it with a look up
            else we apply the host name rules and skip the look up

        The rules for the host field are:
        - Dashes are allowed, but a level cannot start or end with a dash, '-'
        - Only the left most level may contain special characters: '*','?' and '[]'
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']

        with nfs_share_config(nfsid):
            if ExpectedToPass:
                call('sharing.nfs.update', nfsid, {'hosts': hostlist})
            else:
                with pytest.raises(ValidationErrors) as re:
                    call('sharing.nfs.update', nfsid, {'hosts': hostlist})
                assert FailureMsg in str(re.value.errors[0])

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)

            # Check the exports file
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            exports_hosts = [x['host'] for x in parsed[0]['opts']]
            if ExpectedToPass:
                # The entry should be present
                diff = set(hostlist) ^ set(exports_hosts)
                assert len(diff) == 0, f'diff: {diff}, exports: {parsed}'
            else:
                # The entry should not be present
                assert len(exports_hosts) == 1, str(parsed)

    def test_share_ro(self, start_nfs, nfs_dataset_and_share):
        """
        Verify that toggling `ro` will cause appropriate change in
        exports file. We also verify with write tests on a local mount.
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']

        # Make sure we end up in the original state with 'rw'
        # try:
        with nfs_share_config(nfsid) as share_data:
            # Confirm 'rw' initial state and create a file and dir
            assert share_data['ro'] is False
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            assert "rw" in parsed[0]['opts'][0]['parameters'], str(parsed)

            # Mount the share locally and create a file and dir
            with SSH_NFS(truenas_server.ip, NFS_PATH,
                         user=user, password=password, ip=truenas_server.ip) as n:
                n.create("testfile_should_pass")
                n.mkdir("testdir_should_pass")

            # Change to 'ro'
            call('sharing.nfs.update', nfsid, {'ro': True})

            # Confirm 'ro' state and behavior
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            assert "rw" not in parsed[0]['opts'][0]['parameters'], str(parsed)

            # Attempt create and delete
            with SSH_NFS(truenas_server.ip, NFS_PATH,
                         user=user, password=password, ip=truenas_server.ip) as n:
                with pytest.raises(RuntimeError) as re:
                    n.create("testfile_should_fail")
                    assert False, "Should not have been able to create a new file"
                assert 'cannot touch' in str(re), re

                with pytest.raises(RuntimeError) as re:
                    n.mkdir("testdir_should_fail")
                    assert False, "Should not have been able to create a new directory"
                assert 'cannot create directory' in str(re), re

    def test_share_maproot(self, start_nfs, nfs_dataset_and_share):
        """
        root squash is always enabled, and so maproot accomplished through
        anonuid and anongid

        Sample:
        "/mnt/dozer/NFSV4"\
            *(sec=sys,rw,anonuid=65534,anongid=65534,subtree_check)
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']

        with nfs_share_config(nfsid) as share_data:
            # Confirm we won't compete against mapall
            assert share_data['mapall_user'] is None
            assert share_data['mapall_group'] is None

            # Map root to everybody
            call('sharing.nfs.update', nfsid, {
                'maproot_user': 'nobody',
                'maproot_group': 'nogroup'
            })

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)

            params = parsed[0]['opts'][0]['parameters']
            assert 'anonuid=65534' in params, str(parsed)
            assert 'anongid=65534' in params, str(parsed)
            # TODO: Run test as nobody, expect success

            # Setting maproot_user and maproot_group to root should
            # cause us to append "no_root_squash" to options.
            call('sharing.nfs.update', nfsid, {
                'maproot_user': 'root',
                'maproot_group': 'root'
            })

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            params = parsed[0]['opts'][0]['parameters']
            assert 'no_root_squash' in params, str(parsed)
            assert not any(filter(lambda x: x.startswith('anon'), params)), str(parsed)
            # TODO: Run test as nobody, expect failure

            # Second share should have normal (no maproot) params.
            second_share = f'/mnt/{pool_name}/second_share'
            with nfs_dataset('second_share'):
                with nfs_share(second_share):
                    parsed = parse_exports()
                    assert len(parsed) == 2, str(parsed)

                    params = parsed[0]['opts'][0]['parameters']
                    assert 'no_root_squash' in params, str(parsed)

                    params = parsed[1]['opts'][0]['parameters']
                    assert 'no_root_squash' not in params, str(parsed)
                    assert not any(filter(lambda x: x.startswith('anon'), params)), str(parsed)

        # After share config restore, confirm expected settings
        parsed = parse_exports()
        assert len(parsed) == 1, str(parsed)
        params = parsed[0]['opts'][0]['parameters']

        assert not any(filter(lambda x: x.startswith('anon'), params)), str(parsed)

    def test_share_mapall(self, start_nfs, nfs_dataset_and_share):
        """
        mapall is accomplished through anonuid and anongid and
        setting 'all_squash'.

        Sample:
        "/mnt/dozer/NFSV4"\
            *(sec=sys,rw,all_squash,anonuid=65534,anongid=65534,subtree_check)
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None
        nfsid = nfs_dataset_and_share['nfsid']

        with nfs_share_config(nfsid) as share_data:
            # Confirm we won't compete against maproot
            assert share_data['maproot_user'] is None
            assert share_data['maproot_group'] is None

            call('sharing.nfs.update', nfsid, {
                'mapall_user': 'nobody',
                'mapall_group': 'nogroup'
            })

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)

            params = parsed[0]['opts'][0]['parameters']
            assert 'anonuid=65534' in params, str(parsed)
            assert 'anongid=65534' in params, str(parsed)
            assert 'all_squash' in params, str(parsed)

        # After share config restore, confirm settings
        parsed = parse_exports()
        assert len(parsed) == 1, str(parsed)
        params = parsed[0]['opts'][0]['parameters']

        assert not any(filter(lambda x: x.startswith('anon'), params)), str(parsed)
        assert 'all_squash' not in params, str(parsed)

    def test_subtree_behavior(self, start_nfs, nfs_dataset_and_share):
        """
        If dataset mountpoint is exported rather than simple dir,
        we disable subtree checking as an optimization. This check
        makes sure we're doing this as expected:

        Sample:
        "/mnt/dozer/NFSV4"\
            *(sec=sys,rw,no_subtree_check)
        "/mnt/dozer/NFSV4/foobar"\
            *(sec=sys,rw,subtree_check)
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        with directory(f'{NFS_PATH}/sub1') as tmp_path:
            with nfs_share(tmp_path, {'hosts': ['127.0.0.1']}):
                parsed = parse_exports()
                assert len(parsed) == 2, str(parsed)

                assert parsed[0]['path'] == NFS_PATH, str(parsed)
                assert 'no_subtree_check' in parsed[0]['opts'][0]['parameters'], str(parsed)

                assert parsed[1]['path'] == tmp_path, str(parsed)
                assert 'subtree_check' in parsed[1]['opts'][0]['parameters'], str(parsed)

    def test_nonroot_behavior(self, start_nfs, nfs_dataset_and_share):
        """
        If global configuration option "allow_nonroot" is set, then
        we append "insecure" to each exports line.
        Since this is a global option, it triggers an nfsd restart
        even though it's not technically required.
        Linux will, by default, mount using a priviledged port (1..1023)
        MacOS NFS mounts do not follow this 'standard' behavior.

        Four conditions to test:
            server:  secure       (e.g. allow_nonroot is False)
                client: resvport   -> expect to pass.
                client: noresvport -> expect to fail.
            server: insecure    (e.g. allow_nonroot is True)
                client: resvport   -> expect to pass.
                client: noresvport -> expect to pass

        Sample:
        "/mnt/dozer/NFSV4"\
            *(sec=sys,rw,insecure,no_subtree_check)
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        def get_client_nfs_port():
            '''
            Output from netstat -nt looks like:
                tcp        0      0 127.0.0.1:50664         127.0.0.1:6000          ESTABLISHED
            The client port is the number after the ':' in the 5th column
            '''
            rv = (None, None)
            res = ssh("netstat -nt")
            for line in str(res).splitlines():
                # The server will listen on port 2049
                if f"{truenas_server.ip}:2049" == line.split()[3]:
                    rv = (line, line.split()[4].split(':')[1])
            return rv

        # Verify that NFS server configuration is as expected
        with nfs_config() as nfs_conf_orig:

            # --- Test: allow_nonroot is False ---
            assert nfs_conf_orig['allow_nonroot'] is False, nfs_conf_orig

            # Confirm setting in /etc/exports
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            assert 'insecure' not in parsed[0]['opts'][0]['parameters'], str(parsed)

            # Confirm we allow mounts from 'root' ports
            with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
                client_port = get_client_nfs_port()
                assert client_port[1] is not None, f"Failed to get client port: f{client_port[0]}"
                assert int(client_port[1]) < 1024, \
                    f"client_port is not in 'root' range: {client_port[1]}\n{client_port[0]}"

            # Confirm we block mounts from 'non-root' ports
            with pytest.raises(RuntimeError) as re:
                with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, options=['noresvport'],
                             user=user, password=password, ip=truenas_server.ip):
                    pass
                # We should not get to this assert
                assert False, "Unexpected success with mount"
            assert 'Operation not permitted' in str(re), re

            # --- Test: allow_nonroot is True ---
            new_nfs_conf = call('nfs.update', {"allow_nonroot": True})
            assert new_nfs_conf['allow_nonroot'] is True, new_nfs_conf

            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            assert 'insecure' in parsed[0]['opts'][0]['parameters'], str(parsed)

            # Confirm we allow mounts from 'root' ports
            with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
                client_port = get_client_nfs_port()
                assert client_port[1] is not None, "Failed to get client port"
                assert int(client_port[1]) < 1024, \
                    f"client_port is not in 'root' range: {client_port[1]}\n{client_port[0]}"

            # Confirm we allow mounts from 'non-root' ports
            with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, options=['noresvport'],
                         user=user, password=password, ip=truenas_server.ip):
                client_port = get_client_nfs_port()
                assert client_port[1] is not None, "Failed to get client port"
                assert int(client_port[1]) >= 1024, \
                    f"client_port is not in 'non-root' range: {client_port[1]}\n{client_port[0]}"

        # Confirm setting was returned to original state
        parsed = parse_exports()
        assert len(parsed) == 1, str(parsed)
        assert 'insecure' not in parsed[0]['opts'][0]['parameters'], str(parsed)

    def test_syslog_filters(self, start_nfs, nfs_dataset_and_share):
        """
        This test checks the function of the mountd_log setting to filter
        rpc.mountd messages that have priority DEBUG to NOTICE.
        We performing loopback mounts on the remote TrueNAS server and
        then check the syslog for rpc.mountd messages.  Outside of SSH_NFS
        we test the umount case.
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        with nfs_config():

            # The effect is much more clear if there are many mountd.
            # We can force this by configuring many nfsd
            call("nfs.update", {"servers": 24})

            # Confirm default setting: mountd logging enabled
            call("nfs.update", {"mountd_log": True})

            # Add dummy entries to avoid false positives
            for i in range(10):
                ssh(f'logger "====== {i}: NFS test_48_syslog_filters (with) ======"')

            # Local mount to create some entries in syslog
            with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
                pass
            num_tries = 10
            found = False
            res = ""
            while not found and num_tries > 0:
                numlines = 3 * (10 - num_tries) + 5
                res = ssh(f"tail -{numlines} /var/log/syslog")
                if "rpc.mountd" in res:
                    found = True
                    break
                num_tries -= 1
                sleep(10 - num_tries)

            assert found, f"Expected to find 'rpc.mountd' in the output but found:\n{res}"

            # NOTE: Additional mountd messages will get logged on unmount at the exit of the 'with'

            # Disable mountd logging
            call("nfs.update", {"mountd_log": False})

            # Add dummy entries to avoid false positives
            for i in range(10):
                ssh(f'logger "====== {i}: NFS test_48_syslog_filters (without) ======"')

            # This mount should not generate messages
            with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
                pass
            # with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
            # wait a few seconds to make sure syslog has a chance to flush log messages
            sleep(4)
            res = ssh("tail -10 /var/log/syslog")
            assert "rpc.mountd" not in res, f"Did not expect to find 'rpc.mountd' in the output but found:\n{res}"

            # Get a second chance to catch mountd messages on the umount.  They should not be present.
            sleep(4)
            res = ssh("tail -10 /var/log/syslog")
            assert "rpc.mountd" not in res, f"Did not expect to find 'rpc.mountd' in the output but found:\n{res}"

    def test_client_status(self, start_nfs, nfs_dataset_and_share):
        """
        This test checks the function of API endpoints to list NFSv3 and
        NFSv4 clients by performing loopback mounts on the remote TrueNAS
        server and then checking client counts. Due to inherent imprecision
        of counts over NFSv3 protcol (specifically with regard to decrementing
        sessions) we only verify that count is non-zero for NFSv3.
        """
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        with SSH_NFS(truenas_server.ip, NFS_PATH, vers=3, user=user, password=password, ip=truenas_server.ip):
            res = call('nfs.get_nfs3_clients', [], {'count': True})
            assert int(res) != 0

        with SSH_NFS(truenas_server.ip, NFS_PATH, vers=4, user=user, password=password, ip=truenas_server.ip):
            res = call('nfs.get_nfs4_clients', [], {'count': True})
            assert int(res) == 1, f"Expected to find 1, but found {int(res)}"

    @pytest.mark.parametrize('type,data', [
        ('InvalidAssignment', [
            {'maproot_user': 'baduser'}, 'maproot_user', 'User not found: baduser'
        ]),
        ('InvalidAssignment', [
            {'maproot_group': 'badgroup'}, 'maproot_user', 'This field is required when map group is specified'
        ]),
        ('InvalidAssignment', [
            {'mapall_user': 'baduser'}, 'mapall_user', 'User not found: baduser'
        ]),
        ('InvalidAssignment', [
            {'mapall_group': 'badgroup'}, 'mapall_user', 'This field is required when map group is specified'
        ]),
        ('MissingUser', [
            'maproot_user', 'missinguser'
        ]),
        ('MissingUser', [
            'mapall_user', 'missinguser'
        ]),
        ('MissingGroup', [
            'maproot_group', 'missingroup'
        ]),
        ('MissingGroup', [
            'mapall_group', 'missingroup'
        ]),
    ])
    def test_invalid_user_group_mapping(self, start_nfs, nfs_dataset_and_share, type, data):
        '''
        Verify we properly trap and handle invalid user and group mapping
        Two conditions:
            1) Catch invalid assignments
            2) Catch invalid settings at NFS start
        '''
        assert start_nfs is True
        assert nfs_dataset_and_share['nfsid'] is not None

        ''' Local helper routine '''
        def run_missing_usrgrp_test(usrgrp, tmp_path, share, usrgrpInst):
            parsed = parse_exports()
            assert len(parsed) == 2, str(parsed)
            this_share = [entry for entry in parsed if entry['path'] == f'{tmp_path}']
            assert len(this_share) == 1, f"Did not find share {tmp_path}.\nexports = {parsed}"

            # Remove the user/group and restart nfs
            call(f'{usrgrp}.delete', usrgrpInst['id'])
            call('service.restart', 'nfs')

            # An alert should be generated
            alerts = call('alert.list')
            this_alert = [entry for entry in alerts if entry['klass'] == "NFSexportMappingInvalidNames"]
            assert len(this_alert) == 1, f"Did not find alert for 'NFSexportMappingInvalidNames'.\n{alerts}"

            # The NFS export should have been removed
            parsed = parse_exports()
            assert len(parsed) == 1, str(parsed)
            this_share = [entry for entry in parsed if entry['path'] == f'{tmp_path}']
            assert len(this_share) == 0, f"Unexpectedly found share {tmp_path}.\nexports = {parsed}"

            # Modify share to map with a built-in user or group and restart NFS
            call('sharing.nfs.update', share, {data[0]: "ftp"})
            call('service.restart', 'nfs')

            # The alert should be cleared
            alerts = call('alert.list')
            this_alert = [entry for entry in alerts if entry['key'] == "NFSexportMappingInvalidNames"]
            assert len(this_alert) == 0, f"Unexpectedly found alert 'NFSexportMappingInvalidNames'.\n{alerts}"

            # Share should have been restored
            parsed = parse_exports()
            assert len(parsed) == 2, str(parsed)
            this_share = [entry for entry in parsed if entry['path'] == f'{tmp_path}']
            assert len(this_share) == 1, f"Did not find share {tmp_path}.\nexports = {parsed}"

        ''' Test Processing '''
        with directory(f'{NFS_PATH}/sub1') as tmp_path:

            if type == 'InvalidAssignment':
                payload = {'path': tmp_path} | data[0]
                with pytest.raises(ValidationErrors) as ve:
                    call("sharing.nfs.create", payload)
                assert ve.value.errors == [ValidationError('sharingnfs_create.' + f'{data[1]}', data[2], 22)]

            elif type == 'MissingUser':
                usrname = data[1]
                testkey, testval = data[0].split('_')

                usr_payload = {'username': usrname, 'full_name': usrname,
                               'group_create': True, 'password': 'abadpassword'}
                mapping = {data[0]: usrname}
                with create_user(usr_payload) as usrInst:
                    with nfs_share(tmp_path, mapping) as share:
                        run_missing_usrgrp_test(testval, tmp_path, share, usrInst)

            elif type == 'MissingGroup':
                # Use a built-in user for the group test
                grpname = data[1]
                testkey, testval = data[0].split('_')

                mapping = {f"{testkey}_user": 'ftp', data[0]: grpname}
                with create_group({'name': grpname}) as grpInst:
                    with nfs_share(tmp_path, mapping) as share:
                        run_missing_usrgrp_test(testval, tmp_path, share, grpInst)

    def test_service_protocols(self, start_nfs):
        """
        This test verifies that changing the `protocols` option generates expected
        changes in nfs kernel server config.  In most cases we will also confirm
        the settings have taken effect.

        For the time being this test will also exercise the deprecated `v4` option
        to the same effect, but this will later be removed.

        NFS must be enabled for this test to succeed as while the config (i.e.
        database) will be updated regardless, the server config file will not
        be updated.
        TODO: Add client side tests
        """
        assert start_nfs is True

        # Multiple restarts cause systemd failures.  Reset the systemd counters.
        reset_svcs("nfs-idmapd nfs-mountd nfs-server rpcbind rpc-statd")

        with nfs_config() as nfs_conf_orig:
            # Check existing config (both NFSv3 & NFSv4 configured)
            assert "NFSV3" in nfs_conf_orig['protocols'], nfs_conf_orig
            assert "NFSV4" in nfs_conf_orig['protocols'], nfs_conf_orig
            s = parse_server_config()
            assert s['nfsd']["vers3"] == 'y', str(s)
            assert s['nfsd']["vers4"] == 'y', str(s)
            confirm_nfs_version(['3', '4'])

            # Turn off NFSv4 (v3 on)
            new_config = call('nfs.update', {"protocols": ["NFSV3"]})
            assert "NFSV3" in new_config['protocols'], new_config
            assert "NFSV4" not in new_config['protocols'], new_config
            s = parse_server_config()
            assert s['nfsd']["vers3"] == 'y', str(s)
            assert s['nfsd']["vers4"] == 'n', str(s)

            # Confirm setting has taken effect: v4->off, v3->on
            confirm_nfs_version(['3'])

            with pytest.raises(ValidationError) as ve:
                call("nfs.update", {"protocols": []})
            assert "nfs_update.protocols" == ve.value.attribute
            assert "at least one" in str(ve.value)

            # Turn off NFSv3 (v4 on)
            new_config = call('nfs.update', {"protocols": ["NFSV4"]})
            assert "NFSV3" not in new_config['protocols'], new_config
            assert "NFSV4" in new_config['protocols'], new_config
            s = parse_server_config()
            assert s['nfsd']["vers3"] == 'n', str(s)
            assert s['nfsd']["vers4"] == 'y', str(s)

            # Confirm setting has taken effect: v4->on, v3->off
            confirm_nfs_version(['4'])

        # Finally, confirm both are re-enabled
        nfs_conf = call('nfs.config')
        assert "NFSV3" in nfs_conf['protocols'], nfs_conf
        assert "NFSV4" in nfs_conf['protocols'], nfs_conf
        s = parse_server_config()
        assert s['nfsd']["vers3"] == 'y', str(s)
        assert s['nfsd']["vers4"] == 'y', str(s)

        # Confirm setting has taken effect: v4->on, v3->on
        confirm_nfs_version(['3', '4'])

    def test_service_udp(self, start_nfs):
        """
        This test verifies the udp config is NOT in the DB and
        that it is NOT in the etc file.
        """
        assert start_nfs is True

        # The 'udp' setting should have been removed
        nfs_conf = call('nfs.config')
        assert nfs_conf.get('udp') is None, nfs_conf

        s = parse_server_config()
        assert s.get('nfsd', {}).get('udp') is None, s

    def test_service_ports(self, start_nfs):
        """
        This test verifies that we can set custom port and the
        settings are reflected in the relevant files and are active.
        """
        assert start_nfs is True

        # Make custom port selections
        nfs_conf = call("nfs.update", {
            "mountd_port": 618,
            "rpcstatd_port": 871,
            "rpclockd_port": 32803,
        })
        assert nfs_conf['mountd_port'] == 618
        assert nfs_conf['rpcstatd_port'] == 871
        assert nfs_conf['rpclockd_port'] == 32803

        # Compare DB with setting in /etc/nfs.conf.d/local.conf
        with nfs_config() as config_db:
            s = parse_server_config()
            assert int(s['mountd']['port']) == config_db["mountd_port"], str(s)
            assert int(s['statd']['port']) == config_db["rpcstatd_port"], str(s)
            assert int(s['lockd']['port']) == config_db["rpclockd_port"], str(s)

            # Confirm port settings are active
            confirm_rpc_port('mountd', config_db["mountd_port"])
            confirm_rpc_port('status', config_db["rpcstatd_port"])
            confirm_rpc_port('nlockmgr', config_db["rpclockd_port"])

    def test_runtime_debug(self, start_nfs):
        """
        This validates that the private NFS debugging API works correctly.
        """
        assert start_nfs is True
        disabled = {"NFS": ["NONE"], "NFSD": ["NONE"], "NLM": ["NONE"], "RPC": ["NONE"]}
        enabled = {"NFS": ["PROC", "XDR", "CLIENT", "MOUNT", "XATTR_CACHE"],
                   "NFSD": ["ALL"],
                   "NLM": ["CLIENT", "CLNTLOCK", "SVC"],
                   "RPC": ["CALL", "NFS", "TRANS"]}
        failure = {"RPC": ["CALL", "NFS", "TRANS", "NONE"]}
        try:
            res = call('nfs.get_debug')
            assert res == disabled

            call('nfs.set_debug', enabled)
            res = call('nfs.get_debug')
            assert set(res['NFS']) == set(enabled['NFS']), f"Mismatch on NFS: {res}"
            assert set(res['NFSD']) == set(enabled['NFSD']), f"Mismatch on NFSD: {res}"
            assert set(res['NLM']) == set(enabled['NLM']), f"Mismatch on NLM: {res}"
            assert set(res['RPC']) == set(enabled['RPC']), f"Mismatch on RPC: {res}"

            # Test failure case.  This should generate an ValueError exception on the system
            with pytest.raises(ValueError) as ve:
                call('nfs.set_debug', failure)
            assert 'Cannot specify another value' in str(ve), ve

        finally:
            call('nfs.set_debug', disabled)
            res = call('nfs.get_debug')
            assert res == disabled

    def test_bind_ip(self, start_nfs):
        '''
        This test requires a static IP address
        * Test the private nfs.bindip call
        * Test the actual bindip config setting
        - Confirm setting in conf files
        - Confirm service on IP address
        '''
        assert start_nfs is True

        choices = call("nfs.bindip_choices")
        assert truenas_server.ip in choices

        call("nfs.bindip", {"bindip": [truenas_server.ip]})
        call("nfs.bindip", {"bindip": []})

        # Test config with bindip.  Use choices from above
        # TODO: check with 'nmap -sT <IP>' from the runner.
        with nfs_config() as db_conf:

            # Should have no bindip setting
            nfs_conf = parse_server_config()
            rpc_conf = parse_rpcbind_config()
            assert db_conf['bindip'] == []
            assert nfs_conf['nfsd'].get('host') is None
            assert rpc_conf.get('-h') is None

            # Set bindip
            call("nfs.update", {"bindip": [truenas_server.ip]})

            # Confirm we see it in the nfs and rpc conf files
            nfs_conf = parse_server_config()
            rpc_conf = parse_rpcbind_config()
            assert truenas_server.ip in nfs_conf['nfsd'].get('host'), f"nfs_conf = {nfs_conf}"
            assert truenas_server.ip in rpc_conf.get('-h'), f"rpc_conf = {rpc_conf}"

    @pytest.mark.parametrize('state,expected', [
        (None, 'n'),   # Test default state
        (True, 'y'),
        (False, 'n')
    ])
    def test_manage_gids(self, start_nfs, state, expected):
        '''
        The nfsd_manage_gids setting is called "Support > 16 groups" in the webui.
        It is that and, to a greater extent, defines the GIDs that are used for permissions.

        If NOT enabled, then the expectation is that the groups to which the user belongs
        are defined on the _client_ and NOT the server.  It also means groups to which the user
        belongs are passed in on the NFS commands from the client.  The file object GID is
        checked against the passed in list of GIDs.  This is also where the 16 group
        limitation is enforced.  The NFS protocol allows passing up to 16 groups per user.

        If nfsd_manage_gids is enabled, the groups to which the user belong are defined
        on the server.  In this condition, the server confirms the user is a member of
        the file object GID.

        NAS-126067:  Debian changed the 'default' setting to manage_gids in /etc/nfs.conf
        from undefined to "manage_gids = y".

        TEST:   Confirm manage_gids is set in /etc/nfs.conf.d/local/conf for
                both the enable and disable states

        TODO: Add client-side and server-side test from client when available
        '''
        assert start_nfs is True
        with nfs_config():

            if state is not None:
                sleep(3)  # In Cobia: Prevent restarting NFS too quickly.
                call("nfs.update", {"userd_manage_gids": state})

            s = parse_server_config()
            assert s['mountd']['manage-gids'] == expected, str(s)

    def test_v4_domain(self, start_nfs):
        '''
        The v4_domain configuration item maps to the 'Domain' setting in
        the [General] section of /etc/idmapd.conf.
        It is described as:
            The local NFSv4 domain name. An NFSv4 domain is a namespace
            with a unique username<->UID and groupname<->GID mapping.
            (Default: Host's fully-qualified DNS domain name)
        '''
        assert start_nfs is True

        with nfs_config() as nfs_db:
            # By default, v4_domain is not set
            assert nfs_db['v4_domain'] == "", f"Expected zero-len string, but found {nfs_db['v4_domain']}"
            s = parse_server_config("idmapd")
            assert s['General'].get('Domain') is None, f"'Domain' was not expected to be set: {s}"

            # Make a setting change and confirm
            db = call('nfs.update', {"v4_domain": "ixsystems.com"})
            assert db['v4_domain'] == 'ixsystems.com', f"v4_domain failed to be updated in nfs DB: {db}"
            s = parse_server_config("idmapd")
            assert s['General'].get('Domain') == 'ixsystems.com', f"'Domain' failed to be updated in idmapd.conf: {s}"

    class TestSubtreeShares:
        """
        Wrap a class around test_37 to allow calling the fixture only once
        in the parametrized test
        """

        # TODO: Work up a valid IPv6 test
        # res = SSH_TEST(f"ip address show {interface} | grep inet6", user, password, ip)
        # ipv6_network = str(res['output'].split()[1])
        # ipv6_host = ipv6_network.split('/')[0]

        @pytest.fixture(scope='class')
        def dataset_and_dirs(self):
            """
            Create a dataset and an NFS share for it for host 127.0.0.1 only
            In the dataset, create directories: dir1, dir2, dir3
            In each directory, create subdirs: subdir1, subdir2, subdir3
            """

            # Characteristics of expected error messages
            err_strs = [
                ["Another share", "everybody"],
                ["exported to everybody", "another share"],
                ["Another share", "same path"],
                ["This or another", "overlaps"],
                ["Another NFS share already exports"],
                ["Symbolic links"]
            ]

            vol0 = f'/mnt/{pool_name}/VOL0'
            with nfs_dataset('VOL0'):
                # Top level shared to narrow host
                with nfs_share(vol0, {'hosts': ['127.0.0.1']}):
                    # Get the initial list of entries for the cleanup test
                    contents = call('sharing.nfs.query')
                    startIdList = [item.get('id') for item in contents]

                    # Create the dirs
                    dirs = ["everybody_1", "everybody_2",
                            "limited_1", "limited_2",
                            "dir_1", "dir_2"]
                    subdirs = ["subdir1", "subdir2", "subdir3"]
                    try:
                        for dir in dirs:
                            ssh(f"mkdir -p {vol0}/{dir}")
                            for subdir in subdirs:
                                ssh(f"mkdir -p {vol0}/{dir}/{subdir}")
                                # And symlinks
                                ssh(f"ln -sf {vol0}/{dir}/{subdir} {vol0}/{dir}/symlink2{subdir}")

                        yield vol0, err_strs
                    finally:
                        # Remove the created dirs
                        for dir in dirs:
                            ssh(f"rm -rf {vol0}/{dir}")

                        # Remove the created shares
                        contents = call('sharing.nfs.query')
                        endIdList = [item.get('id') for item in contents]
                        [call('sharing.nfs.delete', id) for id in endIdList if id not in startIdList]

        @pytest.mark.parametrize("dirname,isHost,HostOrNet,ExpectedToPass, ErrFormat", [
            ("everybody_1", True, ["*"], True, None),                    # 0: Host - Test NAS-120957
            ("everybody_2", True, ["*"], True, None),                    # 1: Host - Test NAS-120957, allow non-related paths to same hosts
            ("everybody_2", False, ["192.168.1.0/22"], False, 2),        # 2: Network - Already exported to everybody in test 1
            ("limited_1", True, ["127.0.0.1"], True, None),              # 3: Host - Test NAS-123042, allow export of subdirs
            ("limited_2", True, ["127.0.0.1"], True, None),              # 4: Host - Test NAS-120957, NAS-123042
            ("limited_2", True, ["127.0.0.1"], False, 3),                # 4: Host - Test NAS-127220, exact repeat to host
            ("limited_2", True, ["*"], False, 1),                        # 5: Host - Test NAS-123042, export collision, same path, different entry
            ("dir_1", True, ["*.example.com"], True, None),              # 6: Host - Setup for test 7: Host with wildcard
            ("dir_1", True, ["*.example.com"], False, 2),                # 7: Host - Already exported in test 6
            ("dir_1/subdir1", True, ["192.168.0.0"], True, None),        # 8: Host - Setup for test 9: Host as IP address
            ("dir_1/subdir1", True, ["192.168.0.0"], False, 3),          # 9: Host - Alread exported in test 8
            ("dir_1/subdir2", False, ["2001:0db8:85a3:0000:0000:8a2e::/96"], True, None),    # 10: Network - Setup for test 11: IPv6 network range
            ("dir_1/subdir2", True, ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"], False, 3),  # 11: Host - IPv6 network overlap
            ("dir_1/subdir3", True, ["192.168.27.211"], True, None),     # 12: Host - Test NAS-124269, setup for test 13
            ("dir_1/subdir3", False, ["192.168.24.0/22"], False, 3),     # 13: Network - Test NAS-124269, trap network overlap
            ("limited_2/subdir2", True, ["127.0.0.1"], True, None),      # 14: Host - Test NAS-123042, allow export of subdirs
            ("limited_1/subdir2", True, ["*"], True, None),              # 15: Host - Test NAS-123042, everybody
            ("limited_1/subdir2", True, ["*"], False, 4),                # 16: Host - Test NAS-127220, exact repeat to everybody
            ("dir_2/subdir2", False, ["192.168.1.0/24"], True, None),    # 17: Network - Setup for test 17: Wide network range
            ("dir_2/subdir2", False, ["192.168.1.0/32"], False, 3),      # 18: Network - Test NAS-123042 - export collision, overlaping networks
            ("limited_1/subdir3", True, ["192.168.1.0", "*.ixsystems.com"], True, None),  # 19: Host - Test NAS-123042
            ("dir_1/symlink2subdir3", True, ["192.168.0.0"], False, 5),  # 20: Host - Block exporting symlinks
        ])
        def test_subtree_share(self, start_nfs, dataset_and_dirs, dirname, isHost, HostOrNet, ExpectedToPass, ErrFormat):
            """
            Sharing subtrees to the same host can cause problems for
            NFSv3.  This check makes sure a share creation follows
            the rules.
                * First match is applied
                * A new path that is _the same_ as existing path cannot be shared to same 'host'

            For example, the following is not allowed:
            "/mnt/dozer/NFS"\
                fred(rw)
            "/mnt/dozer/NFS"\
                fred(ro)

            Also not allowed are collisions that may result in unexpected share permissions.
            For example, the following is not allowed:
            "/mnt/dozer/NFS"\
                *(rw)
            "/mnt/dozer/NFS"\
                marketing(ro)
            """
            assert start_nfs is True

            vol, err_strs = dataset_and_dirs
            dirpath = f'{vol}/{dirname}'
            if isHost:
                payload = {"path": dirpath, "hosts": HostOrNet}
            else:
                payload = {"path": dirpath, "networks": HostOrNet}

            if ExpectedToPass:
                call("sharing.nfs.create", payload)
            else:
                with pytest.raises(ValidationErrors) as ve:
                    call("sharing.nfs.create", payload)
                errStr = str(ve.value.errors[0])
                # Confirm we have the expected error message format
                for this_substr in err_strs[ErrFormat]:
                    assert this_substr in errStr


def test_threadpool_mode():
    """
    Verify that NFS thread pool configuration can be adjusted
    through private API endpoints.

    This request will fail if NFS server (or NFS client) is
    still running.
    """
    supported_modes = ["AUTO", "PERCPU", "PERNODE", "GLOBAL"]

    for m in supported_modes:
        call('nfs.set_threadpool_mode', m)

        res = call('nfs.get_threadpool_mode')
        assert res == m, res


@pytest.mark.parametrize('exports', ['missing', 'empty'])
def test_missing_or_empty_exports(exports):
    '''
    NAS-123498: Eliminate conditions on exports for service start
    The goal is to make the NFS server behavior similar to the other protocols
    '''
    if exports == 'empty':
        ssh("echo '' > /etc/exports")
    else:  # 'missing'
        ssh("rm -f /etc/exports")

    with nfs_config() as nfs_conf:
        try:
            # Start NFS
            call('service.start', 'nfs')
            sleep(1)
            confirm_nfsd_processes(nfs_conf['servers'])
        finally:
            # Return NFS to stopped condition
            call('service.stop', 'nfs')
            sleep(1)

        # Confirm stopped
        # assert get_nfs_service_state() == "STOPPED"
        assert query_nfs_service()['state'] == "STOPPED"


@pytest.mark.parametrize('expect_NFS_start', [False, True])
def test_files_in_exportsd(expect_NFS_start):
    '''
    Any files in /etc/exports.d are potentially dangerous, especially zfs.exports.
    We implemented protections against rogue exports files.
    - We block starting NFS if there are any files in /etc/exports.d
    - We generate an alert when we detect this condition
    - We clear the alert when /etc/exports.d is empty
    '''
    fail_check = {False: 'ConditionDirectoryNotEmpty=!/etc/exports.d', True: None}

    # Simple helper function for this test
    def set_immutable_state(want_immutable=True):
        call('filesystem.set_immutable', want_immutable, '/etc/exports.d')
        res = call('filesystem.is_immutable', '/etc/exports.d')
        assert res is want_immutable, f"Expected mutable filesystem: {res}"

    try:
        # Setup the test
        set_immutable_state(want_immutable=False)  # Disable immutable

        # Do the 'failing' case first to end with a clean condition
        if not expect_NFS_start:
            ssh("echo 'bogus data' > /etc/exports.d/persistent.file")
            ssh("chattr +i /etc/exports.d/persistent.file")
        else:
            # Restore /etc/exports.d directory to a clean state
            ssh("chattr -i /etc/exports.d/persistent.file")
            ssh("rm -rf /etc/exports.d/*")

        set_immutable_state(want_immutable=True)  # Enable immutable

        set_nfs_service_state('start', expect_NFS_start, fail_check[expect_NFS_start])

    finally:
        # In all cases we want to end with NFS stopped
        set_nfs_service_state('stop')

        # If NFS start is blocked, then an alert should have been raised
        alerts = call('alert.list')
        if not expect_NFS_start:
            # Find alert
            assert any(alert["klass"] == "NFSblockedByExportsDir" for alert in alerts), alerts
        else:  # Alert should have been cleared
            assert not any(alert["klass"] == "NFSblockedByExportsDir" for alert in alerts), alerts


# -------------------- DEBUG --------------------  Test exit state
def test_confirm_nfs_stopped_and_default_config():
    assert query_nfs_service()['state'] == 'STOPPED'
    cur_config = call('nfs.config')
    assert all((set(NFS_CONFIG.default_config[i]) == set(cur_config[i]) for i in NFS_CONFIG.default_config)), cur_config
