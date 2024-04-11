import os
import sys

import pytest
from middlewared.service_exception import CallError
from middlewared.test.integration.assets.pool import dataset
from middlewared.test.integration.utils import call
from middlewared.test.integration.utils.audit import expect_audit_method_calls

sys.path.append(os.getcwd())
from functions import DELETE, POST, PUT

REDACTED_SECRET = '********'


@pytest.fixture(scope='module')
def nfs_audit_dataset(request):
    with dataset('audit-test-nfs') as ds:
        try:
            yield ds
        finally:
            pass


@pytest.mark.parametrize('api', ['ws', 'rest'])
def test_nfs_config_audit(api):
    '''
    Test the auditing of NFS configuration changes
    '''
    bogus_user = 'bogus_user'
    bogus_password = 'boguspassword123'
    initial_nfs_config = call('nfs.config')
    try:
        # CREATE
        with expect_audit_method_calls([{
            'method': 'nfs.add_principal',
            'params': [
                {
                    'username': bogus_user,
                    'password': REDACTED_SECRET,
                }
            ],
            'description': f'Add NFS principal {bogus_user}',
        }]):
            payload = {
                'username': bogus_user,
                'password': bogus_password,
            }
            # The 'add' will fail, but the audit check should pass
            if api == 'ws':
                with pytest.raises(CallError):
                    call('nfs.add_principal', payload)
            elif api == 'rest':
                result = POST('/nfs/add_principal/', payload)
                assert result.status_code != 200, result.text
            else:
                raise ValueError(api)
        # UPDATE
        payload = {
            'mountd_log': not initial_nfs_config['mountd_log'],
            'mountd_port': 618,
            'protocols': ["NFSV4"]
        }
        with expect_audit_method_calls([{
            'method': 'nfs.update',
            'params': [payload],
            'description': 'Update NFS configuration',
        }]):
            if api == 'ws':
                call('nfs.update', payload)
            elif api == 'rest':
                result = PUT('/nfs/', payload)
                assert result.status_code == 200, result.text
            else:
                raise ValueError(api)
    finally:
        # Restore initial state
        restore_payload = {
            'mountd_log': initial_nfs_config['mountd_log'],
            'mountd_port': initial_nfs_config['mountd_port'],
            'protocols': initial_nfs_config['protocols']
        }
        if api == 'ws':
            call('nfs.update', restore_payload)
        elif api == 'rest':
            result = PUT('/nfs/', restore_payload)
            assert result.status_code == 200, result.text
        else:
            raise ValueError(api)


@pytest.mark.parametrize('api', ['ws', 'rest'])
def test_nfs_share_audit(api, nfs_audit_dataset):
    '''
    Test the auditing of NFS share operations
    '''
    nfs_export_path = f"/mnt/{nfs_audit_dataset}"
    try:
        # CREATE
        payload = {
            "comment": "My Test Share",
            "path": nfs_export_path,
            "security": ["SYS"]
        }
        with expect_audit_method_calls([{
            'method': 'sharing.nfs.create',
            'params': [payload],
            'description': f'NFS share create {nfs_export_path}',
        }]):
            if api == 'ws':
                share_config = call('sharing.nfs.create', payload)
            elif api == 'rest':
                results = POST("/sharing/nfs/", payload)
                assert results.status_code == 200, results.text
                share_config = results.json()
            else:
                raise ValueError(api)
        # UPDATE
        payload = {
            "security": []
        }
        with expect_audit_method_calls([{
            'method': 'sharing.nfs.update',
            'params': [
                share_config['id'],
                payload,
            ],
            'description': f'NFS share update {nfs_export_path}',
        }]):
            if api == 'ws':
                share_config = call('sharing.nfs.update', share_config['id'], payload)
            elif api == 'rest':
                results = PUT(f"/sharing/nfs/id/{share_config['id']}/", payload)
                assert results.status_code == 200, results.text
                share_config = results.json()
            else:
                raise ValueError(api)
    finally:
        if share_config is not None:
            # DELETE
            id_ = share_config['id']
            with expect_audit_method_calls([{
                'method': 'sharing.nfs.delete',
                'params': [id_],
                'description': f'NFS share delete {nfs_export_path}',
            }]):
                if api == 'ws':
                    call('sharing.nfs.delete', id_)
                elif api == 'rest':
                    result = DELETE(f'/sharing/nfs/id/{id_}')
                    assert result.status_code == 200, result.text
                else:
                    raise ValueError(api)
