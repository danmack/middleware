import time

import pytest

from middlewared.test.integration.utils.client import client

from functions import determine_vip


@pytest.fixture(scope='module')
def ip_to_use(api_config):
    return api_config['ip1']


@pytest.fixture(scope='module')
def ws_client(api_config, ip_to_use):
    with client(host_ip=ip_to_use, passwd=api_config['password']) as c:
        yield c


@pytest.fixture(scope='module')
def get_payload(api_config, ws_client, ip_to_use):
    # NOTE: This method is assuming that the machine
    # has been handed an IPv4 address from a DHCP server.

    payload = {'ipv4_dhcp': False, 'aliases': []}
    to_validate = [ip_to_use]
    interface = netmask = None
    for i in ws_client.call('interface.query'):
        if all((interface, netmask)):
            break

        # let's get the interface/netmask that was given an address via DHCP
        for j in filter(lambda x: x['address'] == ip_to_use, i['state']['aliases']):
            interface = i['id']
            netmask = j['netmask']
            payload['aliases'].append({'address': ip_to_use, 'netmask': netmask})
            break
        else:
            assert False, f'Unable to determine the interface that has the IP {ip_to_use}'

    vip = None
    if api_config['is_ha']:
        vip = api_config['vip']
        if not vip:
            vip = determine_vip(f'{ip_to_use}/{netmask}')
            if vip is None:
                assert False, 'Unable to find an IP address to be assigned as the VIP'
            else:
                api_config['vip'] = vip
                to_validate.append(vip)

        payload.update({
            'failover_critical': True,
            'failover_group': 1,
            'failover_aliases': [{'address': api_config['ip2']}],
            'failover_virtual_aliases': [{'address': vip}],
        })

    return {
        'iface': interface,
        'iface_config': payload,
        'to_validate': to_validate,
        'vip': vip
    }


def test_001_configure_interface(request, api_config, ws_client, get_payload):
    if api_config['is_ha']:
        # can not make network changes on an HA system unless failover has
        # been explicitly disabled
        ws_client.call('failover.update', {'disabled': True, 'master': True})
        assert ws_client.call('failover.config')['disabled'] is True

    # send the request to configure the interface
    ws_client.call('interface.update', get_payload['iface'], get_payload['iface_config'])

    # 1. verify there are pending changes
    # 2. commit the changes specifying the rollback timer
    # 3. verify that the changes that were committed, need to be "checked" in (finalized)
    # 4. finalize the changes (before the temporary changes are rolled back) (i.e. checkin)
    # 5. verify that there are no more pending interface changes
    assert ws_client.call('interface.has_pending_changes')
    ws_client.call('interface.commit', {'rollback': True, 'checkin_timeout': 10})
    assert ws_client.call('interface.checkin_waiting')
    ws_client.call('interface.checkin')
    assert ws_client.call('interface.checkin_waiting') is None
    assert ws_client.call('interface.has_pending_changes') is False

    if api_config['is_ha']:
        # on HA, keepalived is responsible for configuring the VIP so let's give it
        # some time to settle
        time.sleep(3)

    # We've configured the interface so let's make sure the ip addresses on the interface
    # match reality
    reality = set([i['address'] for i in ws_client.call('interface.ip_in_use', {'ipv4': True})])
    assert reality == set(get_payload['to_validate'])

    if api_config['is_ha']:
        # let's go 1-step further and validate that the VIP accepts connections
        with client(host_ip=get_payload['vip'], passwd=api_config['password']) as c:
            assert c.call('core.ping') == 'pong'
            assert c.call('failover.call_remote', 'core.ping') == 'pong'
