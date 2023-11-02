
import time

import pytest

from middlewared.test.integration.utils import client


def test_apply_and_verify_license(api_config):
    if not api_config['is_ha']:
        pytest.skip('Only Applies to HA Systems')

    with client(host_ip=api_config['ip1'], passwd=api_config['password']) as c:
        with open('ha-license.txt') as f:
            # apply license
            c.call('system.license_update', f.read())

            # verify license is applied
            assert c.call('failover.licensed') is True

            retries = 30
            sleep_time = 1
            for i in range(retries):
                if c.call('failover.call_remote', 'failover.licensed') is False:
                    # we call a hook that runs in a background task
                    # so give it a bit to propagate to other controller
                    # furthermore, our VMs are...well...inconsistent to say the least
                    # so sometimes this is almost instant while others I've 10+ secs
                    time.sleep(sleep_time)
                else:
                    break
            else:
                assert False, f'Timed out after {sleep_time * retries}s waiting on license to sync to standby'
