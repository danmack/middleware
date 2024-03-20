import pytest

from middlewared.test.integration.utils import client


def test_apply_and_verify_license(api_config):
    if not api_config['is_ha']:
        pytest.skip('Only Applies to HA Systems')

    with client(host_ip=api_config['ip1'], passwd=api_config['password']) as c:
        assert c.call('failover.fenced.run_info')['running']
