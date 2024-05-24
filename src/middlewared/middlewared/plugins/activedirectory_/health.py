import errno
import subprocess
import wbclient

from base64 import b64decode
from middlewared.plugins.smb import SMBCmd
from middlewared.plugins.activedirectory_.dns import SRV
from middlewared.schema import accepts, Bool, returns
from middlewared.service import private, Service, ValidationErrors
from middlewared.service_exception import CallError, MatchNotFound
from middlewared.utils.directoryservices.constants import DSStatus
from middlewared.plugins.idmap_.idmap_winbind import WBClient, WBCErr
from middlewared.utils import filter_list


class ActiveDirectoryService(Service):

    class Config:
        service = "activedirectory"
        datastore = "directoryservice.activedirectory"

    @private
    def check_machine_account_keytab(self, dc):
        if self.middleware.call_sync('kerberos.keytab.query', [['name', '=', 'AD_MACHINE_ACCOUNT']]):
            # For now we will short-circuit if user has an AD_MACHINE_ACCOUNT
            return

        # Use net command to build a kerberos keytab from our stored secrets
        results = subprocess.run(['net', 'ads', 'keytab', 'create'], check=False, capture_output=True)
        if results.returncode != 0:
            raise CallError('Failed to generate kerberos keytab from stored secrets: {results.stderr.decode()}')

        self.middleware.call_sync('kerberos.keytab.store_ad_keytab')

    @private
    def check_machine_account_secret(self, dc):
        """
        Check that the machine account password stored in /var/db/system/samba4/secrets.tdb
        is valid and try some basic recovery if file is missing or lacking entry.

        Validation is performed by extracting the machine account password from secrets.tdb
        and using it to perform a temporary kinit.
        """
        ad_config = self.middleware.call_sync('activedirectory.config')
        smb_config = self.middleware.call_sync('smb.config')

        # retrieve the machine account password from secrets.tdb
        try:
            machine_pass = self.middleware.call_sync(
                'directoryservices.secrets.get_machine_secret',
                smb_config['workgroup']
            )
        except FileNotFoundError:
            # our secrets.tdb file has been deleted for some reason
            # unfortunately sometimes users do this when trying to debug issues
            if not self.middleware.call_sync('directoryservices.secrets.restore', smb_config['netbiosname']):
                raise CallError(
                    'File containing AD machine account password has been removed without a viable '
                    'candidate for restoration. Full rejoin of active directory will be required.'
                )

            machine_pass = self.middleware.call_sync(
                'directoryservices.secrets.get_machine_secret',
                smb_config['workgroup']
            )
        except MatchNotFound:
            # secrets.tdb file exists but lacks an entry for our machine account. This is unrecoverable and so
            # we need to try restoring from backup
            if not self.middleware.call_sync('directoryservices.secrets.restore', smb_config['netbiosname']):
                raise CallError(
                    'Stored AD machine account password has been removed without a viable '
                    'candidate for restoration. Full rejoin of active directory will be required.'
                )

            machine_pass = self.middleware.call_sync(
                'directoryservices.secrets.get_machine_secret',
                smb_config['workgroup']
            )

        # By this point we will have some sort of password (b64encoded)
        cred = self.middleware.call_sync('kerberos.get_cred', {
            'dstype': 'DS_TYPE_ACTIVEDIRECTORY',
            'conf': {
                'bindname': smb_config['netbiosname'].upper() + '$',
                'bindpw': b64decode(machine_pass).decode(),
                'domainname': ad_config['domainname']
            }
        })

        # Actual validation of secret will happen here
        self.middleware.call_sync('kerberos.do_kinit', {
            'krb5_cred': cred,
            'kinit-options': {'ccache': 'TEMP', 'kdc_override': {
                'domain': ad_config['domainname'].upper(),
                'kdc': dc
            }}
        })

        try:
            self.middleware.call_sync('kerberos.kdestroy', {'ccache': 'TEMP'})
        except Exception:
            self.logger.debug("Failed to destroy temporary ccache", exc_info=True)
