import asyncio
import struct
import errno

from base64 import b64decode
from middlewared.schema import accepts, Dict, List, OROperator, Ref, returns, Str
from middlewared.service import no_authz_required, Service, private, job
from middlewared.plugins.directoryservices_.all import (
    all_directory_services,
    registered_services_obj,
    get_enabled_ds
)
from middlewared.service_exception import CallError, MatchNotFound
from middlewared.utils.directoryservices.constants import (
    DSStatus, DSType, NSS_Info, SASL_Wrapping, SSL
)

DEPENDENT_SERVICES = ['smb', 'nfs', 'ssh']


class DirectoryServices(Service):
    class Config:
        service = "directoryservices"
        cli_namespace = "directory_service"

    @no_authz_required
    @accepts()
    @returns(Dict(
        'directory_services_states',
        Ref('ds_status', 'activedirectory'),
        Ref('ds_status', 'ldap')
    ))
    def get_state(self):
        """
        `DISABLED` Directory Service is disabled.

        `FAULTED` Directory Service is enabled, but not HEALTHY. Review logs and generated alert
        messages to debug the issue causing the service to be in a FAULTED state.

        `LEAVING` Directory Service is in process of stopping.

        `JOINING` Directory Service is in process of starting.

        `HEALTHY` Directory Service is enabled, and last status check has passed.
        """
        states = {'activedirectory': 'DISABLED', 'ldap': 'DISABLED'}
        for ds_type in registered_services_obj._fields:
            if (ds_obj := getattr(registered_services_obj, ds_type)) is None:
                self.logger.debug("Directory services are unitialized")
                return states

            states[ds_type] = ds_obj.status.name

        # TODO: in future release IPA state will be reported separately from LDAP
        if states['ipa'] != 'DISABLED':
            states['ldap'] = states['ipa']

        return {
            'activedirectory': states['activedirectory'],
            'ldap': states['ldap'] or states['ipa']
        }

    @accepts()
    @job()
    async def cache_refresh(self, job):
        """
        This method refreshes the directory services cache for users and groups that is
        used as a backing for `user.query` and `group.query` methods. The first cache fill in
        an Active Directory domain may take a significant amount of time to complete and
        so it is performed as within a job. The most likely situation in which a user may
        desire to refresh the directory services cache is after new users or groups  to a remote
        directory server with the intention to have said users or groups appear in the
        results of the aforementioned account-related methods.

        A cache refresh is not required in order to use newly-added users and groups for in
        permissions and ACL related methods. Likewise, a cache refresh will not resolve issues
        with users being unable to authenticate to shares.
        """
        return await job.wrap(await self.middleware.call('directoryservices.cache.refresh'))

    @private
    @returns(List(
        'ldap_ssl_choices', items=[
            Str('ldap_ssl_choice', enum=[x.value for x in list(SSL)], default=SSL.USESSL.value, register=True)
        ]
    ))
    async def ssl_choices(self, dstype):
        return [x.value for x in list(SSL)]

    @private
    @returns(List(
        'sasl_wrapping_choices', items=[
            Str('sasl_wrapping_choice', enum=[x.value for x in list(SASL_Wrapping)], register=True)
        ]
    ))
    async def sasl_wrapping_choices(self, dstype):
        return [x.value for x in list(SASL_Wrapping)]

    @private
    @returns(OROperator(
        List('ad_nss_choices', items=[Str(
            'nss_info_ad',
            enum=[x.nss_type for x in NSS_Info if DSType.AD in x.valid_services],
            default=NSS_Info.SFU.nss_type,
            register=True
        )]),
        List('ldap_nss_choices', items=[Str(
            'nss_info_ldap',
            enum=[x.nss_type for x in NSS_Info if DSType.LDAP in x.valid_services],
            default=NSS_Info.RFC2307.nss_type,
            register=True)
        ]),
        name='nss_info_choices'
    ))
    async def nss_info_choices(self, dstype):
        ds = DSType(dstype.lower())
        return [x.nss_type for x in NSS_Info if ds in x.valid_services]

    @private
    async def get_last_password_change(self, domain=None):
        """
        Returns unix timestamp of last password change according to
        the secrets.tdb (our current running configuration), and what
        we have in our database.
        """
        smb_config = await self.middleware.call('smb.config')
        if domain is None:
            domain = smb_config['workgroup']

        try:
            passwd_ts = await self.middleware.call(
                'directoryservices.secrets.last_password_change', domain
            )
        except MatchNotFound:
            passwd_ts = None

        db_secrets = await self.middleware.call('directoryservices.secrets.get_db_secrets')
        server_secrets = db_secrets.get(f"{smb_config['netbiosname_local'].upper()}$")
        if server_secrets is None:
            return {"dbconfig": None, "secrets": passwd_ts}

        try:
            stored_ts_bytes = server_secrets[f'SECRETS/MACHINE_LAST_CHANGE_TIME/{domain.upper()}']
            stored_ts = struct.unpack("<L", b64decode(stored_ts_bytes))[0]
        except KeyError:
            stored_ts = None

        return {"dbconfig": stored_ts, "secrets": passwd_ts}

    async def __kerberos_start_retry(self, retries=10):
        while retries > 0:
            try:
                await self.middleware.call('kerberos.start')
                break
            except CallError as e:
                if e.errno == errno.EAGAIN:
                    self.logger.debug("Failed to start kerberos. Retrying %d more times.",
                                      retries)
                else:
                    self.logger.warning("Failed to start kerberos. Retrying %d more times.",
                                        retries, exc_info=True)
            await asyncio.sleep(1)
            retries -= 1

    @private
    @job()
    async def initialize(self, job, data=None):
        """
        Ensure that secrets.tdb at a minimum exists. If it doesn't exist, try to restore
        from a backup stored in our config file. If this fails, try to use what
        auth info we have to recover the information. If we are in an LDAP
        environment with a samba schema in use, we just need to write the password into
        secrets.tdb.
        """
        if data is None:
            ldap_conf = await self.middleware.call("ldap.config")
            ldap_enabled = ldap_conf['enable']
            ad_enabled = (await self.middleware.call("activedirectory.config"))['enable']
        else:
            ldap_enabled = data['ldap']
            ad_enabled = data['activedirectory']
            if ldap_enabled:
                ldap_conf = await self.middleware.call("ldap.config")

        workgroup = (await self.middleware.call("smb.config"))["workgroup"]
        is_kerberized = ad_enabled

        if not ldap_enabled and not ad_enabled:
            return

        health_check = 'activedirectory.started' if ad_enabled else 'ldap.started'

        has_secrets = await self.middleware.call('directoryservices.secrets.has_domain', workgroup)
        if ad_enabled and not has_secrets:
            self.logger.warning("Domain secrets database does not exist. "
                                "Attempting to restore.")

            if not await self.middleware.call("directoryservices.secrets.restore"):
                self.logger.warning("Failed to restore domain secrets database. "
                                    "Re-joining AD domain may be required.")

        if ldap_enabled and ldap_conf['kerberos_realm']:
            is_kerberized = True

        try:
            await self.middleware.call('idmap.gencache.flush')
        except Exception:
            self.logger.warning('Cache flush failed', exc_info=True)

        if is_kerberized:
            await self.__kerberos_start_retry()

        await self.middleware.call(health_check)

    @private
    def restart_dependent_services(self):
        for svc in self.middleware.call_sync('service.query', [['OR', [
            ['enable', '=', True],
            ['state', '=', 'RUNNING']
        ]], ['service', 'in', DEPENDENT_SERVICES]]):
            self.middleware.call_sync('service.restart', svc['service'])

    @private
    def register_objects(self):
        is_enterprise = self.middleware.call_sync('system.is_enterprise')
        for ds in all_directory_services:
            initialized = ds(self.middleware, is_enterprise)
            setattr(registered_services_obj, initialized.name, initialized)

    @private
    @job(lock='ds_init', lock_queue_size=1)
    def setup(self, job):
        self.register_objects()
        config_in_progress = self.middleware.call_sync("core.get_jobs", [
            ["method", "=", "smb.configure"],
            ["state", "=", "RUNNING"]
        ])
        if config_in_progress:
            job.set_progress(0, "waiting for smb.configure to complete")
            wait_id = self.middleware.call_sync('core.job_wait', config_in_progress[0]['id'])
            wait_id.wait_sync()

        if not self.middleware.call_sync('smb.is_configured'):
            raise CallError('Skipping directory service setup due to SMB service being unconfigured')

        failover_status = self.middleware.call_sync('failover.status')
        if failover_status not in ('SINGLE', 'MASTER'):
            self.logger.debug('%s: skipping directory service setup due to failover status', failover_status)
            job.set_progress(100, f'{failover_status}: skipping directory service setup due to failover status')
            return

        self.middleware.call_sync('sevice.restart', 'idmap')
        if (enabled_ds := get_enabled_ds()) is None:
            job.set_progress(100, "No directory services enabled.")
            return

        enabled_ds.health_check()

        job.set_progress(10, 'Refreshing cache'),
        enabled_ds.fill_cache()

        job.set_progress(75, 'Restarting dependent services')
        self.restart_dependent_services()
        job.set_progress(100, 'Setup complete')

    @accepts()
    @returns(Dict(
        'directoryservice_summary',
        Str('type', enum=[x.value.upper() for x in DSType]),
        Str('ds_status', enum=[x.name for x in DSStatus], register=True),
        Str('ds_status_str', null=True),
        Dict('domain_info', additional_attrs=True),
    ))
    def summary(self):
        if (ds_obj := get_enabled_ds()) is None:
            # directory services are disabled
            return None

        return ds_obj.summary()


async def __init_directory_services(middleware, event_type, args):
    await middleware.call('directoryservices.setup')


async def setup(middleware):
    await middleware.call('directoryservices.register_objects')
    middleware.event_subscribe('system.ready', __init_directory_services)
    middleware.event_register('directoryservices.status', 'Sent on directory service state changes.')
    middleware.event_register('directoryservices.summary', 'Sent on directory service state changes.')
