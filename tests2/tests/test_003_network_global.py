import pytest
from pytest_dependency import depends

from middlewared.test.integration.utils.client import client

from functions import random_hostname


@pytest.fixture(scope='module')
def ip_to_use(api_config):
    return api_config['ip1']


@pytest.fixture(scope='module')
def ws_client(api_config, ip_to_use):
    with client(host_ip=ip_to_use, passwd=api_config['password']) as c:
        yield c


@pytest.fixture(scope='module')
def netinfo(ws_client, api_config):
    """The VMs that are spun-up for our CI tests grab DHCP
    addresses which also include nameservers and a gateway"""
    # TODO: DHCP might not be configured on the system
    # we're pointed to so we can add logic here to make this
    # accept user-provided arguments
    ans = ws_client.call('network.general.summary')
    assert ans['default_routes']
    assert ans['nameservers']

    info = {
        'ipv4gateway': ans['default_routes'][0],  # FIXME: IPv6?
        'hosts': ['fake.host.bad 192.168.1.150', 'another.fake.domain 172.16.50.100'],
    }
    info.update(random_hostname(api_config['is_ha']))
    for idx, nameserver in enumerate(ans['nameservers'], start=1):
        if idx > 3:
            # only 3 nameservers allowed via the API
            break
        else:
            info[f'nameserver{idx}'] = nameserver

    return info


@pytest.mark.dependency(name='NET_CONFIG')
def test_001_set_and_verify_network_global_settings_database(ws_client, netinfo):
    config = ws_client.call('network.configuration.update', netinfo)
    assert all(config[k] == netinfo[k] for k in netinfo)


def test_002_verify_network_global_settings_state(request, ws_client, netinfo):
    depends(request, ['NET_CONFIG'])
    state = ws_client.call('network.configuration.config')['state']
    assert set(state['hosts']) == set(netinfo['hosts'])
    assert state['ipv4gateway'] == netinfo['ipv4gateway']
    for key in filter(lambda x: x.startswith('nameserver'), netinfo):
        assert state[key] == netinfo[key]

    """
    HA isn't fully operational by the time this test runs so testing
    the functionality on the remote node is guaranteed to fail. We
    should probably rearrange order of tests and fix this at some point.
    if ha:
        state = ws_client.call('failover.call_remote', 'network.configuration.config')['state']
        assert set(state['hosts']) == set(netinfo['hosts'])
        assert state['ipv4gateway'] == netinfo['ipv4gateway']
        for key in filter(lambda x: x.startswith('nameserver'), netinfo):
            assert state[key] == netinfo[key]
    """


def test_003_verify_network_general_summary(request, ws_client, netinfo, ip_to_use):
    depends(request, ['NET_CONFIG'])
    for iface, ips in ws_client.call('network.general.summary')['ips'].items():
        if any(i.startswith(ip_to_use) for i in ips['IPV4']):
            break
    else:
        assert False, f'Unable to find {ip_to_use} in network.general.summary'
