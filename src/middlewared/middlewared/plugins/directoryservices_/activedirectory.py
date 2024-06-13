import subprocess

from .base_interface import DirectoryServiceInterface
from middlewared.utils.nss.nss_common import NssModule
from middlewared.utils.directoryservices.ad import (
    get_domain_info,
    get_machine_account_status
)
from middlewared.utils.directoryservices.ad_constants import (
    MAX_SERVER_TIME_OFFSET
)
from middlewared.utils.directoryservices.constants import DSType
from middlewared.utils.directoryservices.health import (
    ADHealthCheckFailReason,
    ADHealthError
)
from middlewared.utils.directoryservices.krb5_constants import krb5ccache
from middlewared.plugins.smb_.constants import SMBCmd, SMBPath
from middlewared.plugins.idmap_.idmap_winbind import WBClient
from middlewared.service_exception import CallError
from time import time
from typing import Optional


class ADDirectoryService(DirectoryServiceInterface):
    _machine_account = None

    def __init__(self, middleware, is_enterprise):
        super().__init__(
            middleware=middleware,
            ds_type=DSType.AD,
            datastore_name='directoryservice.activedirectory',
            datastore_prefix='ad_',
            has_sids=True,
            has_dns_update=True,
            is_enterprise=is_enterprise,
            nss_module=NssModule.WINBIND.name
        )

    def _get_fqdn(self) -> str:
        """ Retrieve server hostname for DNS register / unregister """
        smb_conf = self.call_sync('smb.config')
        conf = self.config
        return f'{smb["netbiosname"]}.{conf["domainname"]}'

    def _domain_info(
        self,
        domain_in: Optional[str] = None,
        retry: Optional[bool] = True
    ) -> dict:
        """
        Use libads to query information about the specified domain.
        If it is left unspecifed then the value of `domainname` in the
        AD configuration will be used.

        See get_domain_info() documentation for keys and expected values
        """
        domain = domain_in or self.config['domainname']
        try:
            domain_info = get_domain_info(domain)
        except Exception as e:
            if not retry:
                raise e from None

            # samba's gencache may have a stale server affinity entry
            # or stale negative cache results
            self.call_sync('idmap.gencache.flush')
            domain_info = get_domain_info(domain)

        return domain_info

    def test_join(self, workgroup: str):
        """
        Test to see whether we're currently joined to an AD domain.
        """
        netads = subprocess.run([
            SMBCmd.NET.value,
            '--use-kerberos', 'required',
            '--use-krb5-ccache', krb5ccache.SYSTEM.value,
            '-w', workgroup,
            '-d', '5',
            'ads', 'testjoin'
        ], check=False, capture_output=True)

        if netads.returncode == 0:
            return True

        err_msg = netads.stderr.decode()
        log_path = f'{SMBPath.LOGDIR.platform()}/domain_testjoin_{time()}.log'
        with open(log_path, 'w') as f:
            f.write(err_msg)
            f.flush()

        # We only want to forcible rejoin active directory if it's clear
        # that our credentials are wrong or the computer account doesn't
        # exist
        for err_str in (
            '0xfffffff6',
            'LDAP_INVALID_CREDENTIALS',
            'The name provided is not a properly formed account name',
            'The attempted logon is invalid.'
        ):
            if err_str in err_msg:
                return False

        raise CallError(
            'Attempt to check AD join status failed unexpectedly. '
            f'Please review logs at {log_path} and file a bug report.'
        )

    def _do_post_join_actions(self, force: bool):
        out = self.register_dns(force)
        self.set_spn(['nfs'])
        self.call_sync('directoryservices.secrets.backup')

        return out

    def join(self, workgroup: str, force: Optional[bool] = False) -> dict:
        """
        Join an active directory domain. Requires admin kerberos ticket.
        If post-join operations fail, then we attempt to roll back changes on
        the DC.
        """
        self._assert_is_active()

        conf = self.config

        cmd = [
            SMBCmd.NET.value,
            '--use-kerberos', 'required',
            '--use-krb5-ccache', krb5ccache.SYSTEM.value,
            '-U', conf['bindname'],
            '-d', '5',
            'ads', 'testjoin',
        ]

        if conf['createcomputer']:
            cmd.append(f'createcomputer={conf["createcomputer"]}')

        cmd.extend([
            '--no-dns-updates', conf['domainname']
        ])

        netads = subprocess.run(cmd, check=False, capture_output=True)
        if netads.returncode != 0:
            err_msg = netads.stderr.decode().split(':', 1)[1]
            raise CallError(err_msg)

        # we've now successfully joined AD and can proceed with post-join
        # operations
        try:
            return self._do_post_join_actions(force)
        except Exception as e:
            # We failed to set up DNS / keytab cleanly
            # roll back and present user with error
            self.leave(conf['bindname'])
            self.call_sync('idmap.gencache.flush')
            raise e from None

    def leave(self, username: str) -> bool:
        """ Delete our computer object from active directory """
        self._assert_is_active()
        netads = subprocess.run([
            SMBCmd.NET.value,
            '--use-kerberos', 'required',
            '--use-krb5-ccache', krb5ccache.SYSTEM.value,
            '-U', username,
            'ads', 'leave',
        ], check=False, capture_output=True)

        # remove cached machine account information
        self._machine_account = None
        if netads.returncode == 0:
            return True

        self.logger.warning(
            'Failed to cleanly leave domain: %s', netads.stderr.decode()
        )
        return False

    def summary(self) -> dict:
        """ provide basic summary of AD status """
        status = self.status

        try:
            domain_info = self._domain_info()
        except Exception:
            self.logger.warning('Failed to retrieve domain information', exc_info=True)
            domain_info = None

        if domain_info:
            if not self._machine_account:
                try:
                    data = get_machine_account_status(
                        domain_info['ldap_server']
                    )
                    self._machine_account = data
                    domain_info['machine_account'] = data.copy()
                except Exception:
                    self.logger.warning('Failed to retrieve AD machine account status', exc_info=True)
            else:
                domain_info['machine_account'] = self._machine_account.copy()

        return {
            'type': self.name.upper(),
            'status': status.name,
            'status_msg': self._faulted_reason,
            'domain_info': domain_info
        }

    def set_spn(self, spn_list: list) -> None:
        """
        Create service entries on domain controller and update our
        stored kerberos keytab to reflect them. Currently only NFS
        is supported, but we may expand this in the future.
        """
        self._assert_is_active()

        for service in spn_list:
            if service not in ('nfs'):
                raise ValueError(f'{service}: not a supported service')

            cmd = [
                SMBCmd.NET.value,
                '--use-kerberos', 'required',
                '--use-krb5-ccache', krb5ccache.SYSTEM.value,
                'ads', 'keytab',
                'add_update_ads', service
            ]

            netads = subprocess.run(cmd, check=False, capture_output=True)
            if netads.returncode != 0:
                raise CallError(
                    'Failed to set spn entry: '
                    f'{netads.stdout.decode().strip()}'
                )

        self.call_sync('kerberos.keytab.store_ad_keytab')

    def _health_check_impl(self):
        """
        Perform basic health checks for AD connection.

        This method is called periodically from our alert framework.
        """

        # We should validate some basic AD configuration before the common
        # kerberos health checks. This will expose issues with clock slew
        # and invalid stored machine account passwords
        try:
            domain_info = self.domain_info()
        except Exception:
            domain_info = None

        if domain_info:
            if domain_info['server_time_offset'] > MAX_SERVER_TIME_OFFSET:
                self._faulted_reason = (
                    'Time offset from Active Directory domain exceeds maximum '
                    'permitted value. This may indicate an NTP misconfiguration.'
                )
                raise ADHealthError(
                    ADHealthCheckFailReason.NTP_EXCESSIVE_SLEW,
                    self._faulted_reason
                )
            try:
                # This performs some basic error recovery attempt
                # by restoring a backed-up copy of our secret
                self.call_sync(
                    'activedirectory.check_machine_account_secret',
                    domain_info['kdc_server']
                )
            except CallError as e:
                self._faulted_reason = e.errmsg
                raise ADHealthError(
                    ADHealthCheckFailReason.AD_SECRET_INVALID,
                    self._faulted_reason
                )

            try:
                # This also performs some basic error recovery
                # by attempting to generate a new keyab based on our
                # stored secret
                self.call_sync(
                    'activedirectory.check_machine_account_keytab',
                    domain_info['kdc_server']
                )
            except CallError as e:
                self._faulted_reason = e.errmsg
                raise ADHealthError(
                    ADHealthCheckFailReason.AD_KEYTAB_INVALID,
                    self._faulted_reason
                )

        # Now for general kerberos health checks
        self._health_check_krb5()

        # Now check that winbindd is started

        if not self.call_sync('service.started', 'idmap'):
            try:
                self.call_sync('service.start', 'idmap', {'silent': False})
            except CallError as e:
                self._faulted_reason = str(e.errmsg)
                raise ADHealthError(
                    ADHealthCheckFailReason.WINBIND_STOPPED,
                    self._faulted_reason
                )

        # Winbind is running and so we can check our netlogon connection
        # First open the libwbclient handle. This should in theory never fail.
        try:
            ctx = WBClient()
        except Exception as e:
            self._faulted_reason = str(e)
            raise ADHealthError(
                ADHealthCheckFailReason.AD_WBCLIENT_FAILURE,
                self._faulted_reason
            )

        # If needed we can replace `ping_dc()` with `check_trust()`
        # for now we're defaulting to lower-cost test unless it gives
        # false reports of being up
        try:
            ctx.ping_dc()
        except Exception as e:
            self._faulted_reason = str(e)
            raise ADHealthError(
                ADHealthCheckFailReason.AD_TRUST_BROKEN,
                self._faulted_reason
            )
