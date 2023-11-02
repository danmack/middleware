import json
import os

import pytest

from constants import API_CFG_FILE


@pytest.fixture(scope='session', autouse=True)
def api_config(request):
    """Returns a dictionary all relevant API configuration
    knobs. This is called once before all tests are run.
    pytest will scope this fixture appropriately so all the
    function in a given test file just needs to be passed
    the name of this fixture.
    (i.e.
        def test_blah(api_config):
            var = api_config['key']
            ...
    )
    """
    data = {'pool_name': 'tank'}
    with open(API_CFG_FILE) as f:
        data.update(json.loads(f.read()))

    return data
