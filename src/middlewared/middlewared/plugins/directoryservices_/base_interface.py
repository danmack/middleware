import dns
import ipaddress
import os
import stat

from copy import deepcopy
from middlewared.utils.itertools import batched
from middlewared.utils.directoryservices import (
    krb5, krb5_constants
)
from middlewared.utils.directoryservices.constants import (
    DSStatus, DSType
)
from middlewared.utils.directoryservices.health import (
    KRB5HealthCheckFailReason, KRB5HealthError
)
from middlewared.utils.nss import pwd, grp
from middlewared.plugins.idmap_.idmap_constants import (
    IDType,
    MAX_REQUEST_LENGTH,
    SID_LOCAL_USER_PREFIX,
    SID_LOCAL_GROUP_PREFIX,
)
from middlewared.service_exception import CallError
from time import monotonic
from typing import Callable, Union, Optional


CONFIG_TIMEOUT = 60
ID_TYPE_BOTH_BACKENDS = ('RID', 'AUTORID')


class DirectoryServiceInterface:
    """
    Base directory services class. This provides common status-related code
    for directory
    """

    __slots__ = (
        '_ds_type',
        '_name',
        '_status',
        '_datastore_name',
        '_datastore_prefix',
        '_middleware',
        '_nss_module',
        '_has_sids',
        '_has_dns_update',
        '_is_enterprise',
        '_faulted_reason',
        '_config'
    )

    def __init__(
        self,
        middleware: object,
        ds_type: DSType,
        datastore_name: str,
        datastore_prefix: str,
        nss_module: str,
        is_enterprise: bool,
        has_sids: Optional[bool] = False,
        has_dns_update: Optional[bool] = False
    ):
        self._middleware = middleware
        self._ds_type = ds_type
        self._name = DSType(ds_type).value
        self._datastore_name = datastore_name
        self._datastore_prefix = datastore_prefix
        self._nss_module = nss_module
        self._has_sids = has_sids
        self._has_dns_update = has_dns_update
        self._is_enterprise = is_enterprise
        self._status = None
        self._faulted_reason = None
        self._config = None

    @property
    def ds_type(self) -> DSType:
        return self._ds_type

    @property
    def name(self) -> str:
        return self._name

    def is_enabled(self) -> bool:
        return self.config['enable']

    def _assert_is_active(self) -> None:
        if self._is_enterprise:
            if self.call_sync('failover_status') not in ('MASTER', 'SINGLE'):
                raise CallError(
                    'This method may only be called on the active storage controller'
                )

    @property
    def status(self) -> DSStatus:
        """
        Return the current status of the directory service.

        In some edge cases this may block for a potentially significant amount
        of time if middleware has been restarted with a "FAULTED" directory
        service.

        Returns DSStatus type
        """
        if self._status is None:
            if not self.is_enabled():
                return DSStatus.DISABLED

            # We are enabled but have never checked our state
            if not self.call_sync('system.ready'):
                # We may still be starting up. Tell everyone
                # we're still "joining" (until we have successful health check)
                return DSStatus.JOINING

            # Health check should initialze state to something
            # relevant (even if it fails)
            try:
                self.health_check()
            except Exception:
                return DSStatus.FAULTED

            return DSStatus.HEALTHY

        return self._status

    @status.setter
    def status(self, state_in: str):
        try:
            _state = DSStatus[state_in]
        except KeyError:
            raise ValueError(
                f'{state_in}: not a valid directory services state '
                f'choices are: [{x.name for x in DSStatus}]'
            )
        match _state:
            case DSStatus.DISABLED:
                # Avoid caching a DISABLED state to force periodic re-checks
                # of someone surreptitously re-enabling the service via
                # datastore plugin or sqlite commands. Unfortunately, there
                # are some old how-to guides from FreeNAS 9 that advise this.
                self._status = None
            case _:
                self._status = _state

    @property
    def logger(self) -> Callable:
        return self._middleware.logger

    @property
    def call_sync(self) -> Callable:
        return self._middleware.call_sync

    @property
    def config(self) -> dict:
        """
        Retrieve cached copy of datastore contents for directory service

        This is primarily used
        """
        if self._config is None or monotonic() > self._config['expires']:
            self.update_config()

        return deepcopy(self._config['config'])

    def update_config(self) -> None:
        """
        Force an update of the in-memory datastore cache
        """
        _conf = self.call_sync('datastore.config', self._datastore_name, {
            'prefix': self._datastore_prefix,
        })
        _conf['enumerate'] = not _conf.pop('disable_freenas_cache', False)

        self._config = {
            'expires': monotonic() + 60,
            'config': _conf
        }

    def _get_fqdn(self) -> str:
        """ Retrieve server hostname for DNS register / unregister """
        ngc = self.call_sync('network.configuration.config')
        return f'{ngc["hostname"]}.{ngc["domain"]}'

    def _get_bindips(self) -> list:
        """
        This method is used to restrict the list of IP addresses to register
        in via nsupdate.
        """
        return None

    def _get_ip_updates(self, fqdn: str, force: Optional[bool] = False) -> list:
        """ Retrieve list of IPs to register in DNS """
        validated_ips = set()
        to_remove_ips = set()

        ips = [i['address'] for i in self.call_sync('interface.ip_in_use')]

        # User may have selected to override which IPs we will register in DNS
        if (bindip := self._get_bindips) is not None:
            to_check = set(bindip) & set(ips)
        else:
            to_check = set(ips)

        for ip in to_check:
            try:
                result = self.middleware.call_sync('dnsclient.reverse_lookup', {
                    'addresses': [ip]
                })
            except dns.resolver.NXDOMAIN:
                # Reverse entry doesn't exist and so we're safe
                validated_ips.add(ip)
                continue

            except dns.resolver.LifetimeTimeout:
                # Exceeding lifetime timeout may often mean that administrator has
                # not configured a reverse zone. This may lead to semi-broken kerberos
                # environment.
                self.logger.warning(
                    '%s: DNS operation timed out while trying to resolve reverse pointer '
                    'for IP address.',
                    ip
                )

            except dns.resolver.NoNameservers:
                self.logger.warning(
                    'No nameservers configured to handle reverse pointer for %s. '
                    'Omitting from list of addresses to register.',
                    ip
                )
                continue

            except Exception:
                # DNS for this IP may be simply wildly misconfigured and time out
                self.logger.warning(
                    'Reverse lookup of %s failed, omitting from list '
                    'of addresses to use for Active Directory purposes.',
                    ip, exc_info=True
                )
                continue

            else:
                if result[0]['target'].casefold() != fqdn.casefold():
                    self.logger.warning(
                        'Reverse lookup of %s points to %s, expected %s',
                        ip, result[0]['target'], fqdn
                    )
                    if not force:
                        continue

                validated_ips.add(ip)

        if force:
            try:
                current_addresses = set([
                    x['address'] for x in
                    self.call_sync('dnsclient.forward_lookup', {
                       'names': [fqdn]
                    })
                ])
            except dns.resolver.NXDOMAIN:
                pass

            to_remove_ips = current_addresses - validated_ips

        return {
            'to_add': validated_ips,
            'to_remove': to_remove_ips,
        }

    def register_dns(
        self,
        force: Optional[bool] = False
    ) -> None:
        """
        Use existing kerberos ticket to register our server
        in DNS for the domain via `nsupdate` + TSIG.
        """
        if not self._has_dns_update:
            raise NotImplementedError

        self._assert_is_active()

        config = self.config
        if not config['allow_dns_updates']:
            # DNS updates have been disabled
            return

        fqdn = self._get_fqdn()
        if force:
            self.unregister_dns(force)

        payload = []
        ip_updates = self.__get_ips_to_register(fqdn, force)
        for ip in ip_updates['to_remove']:
            addr = ipaddress.ip_address(ip)
            payload.append({
                'command': 'DELETE',
                'name': fqdn,
                'address': str(addr),
                'type': 'A' if addr.version == 4 else 'AAAA'
            })

        for ip in ip_updates['to_add']:
            addr = ipaddress.ip_address(ip)
            payload.append({
                'command': 'ADD',
                'name': fqdn,
                'address': str(addr),
                'type': 'A' if addr.version == 4 else 'AAAA'
            })

        try:
            self.middleware.call_sync('dns.nsupdate', {'ops': payload})
        except CallError as e:
            self.logger.warning(
                'Failed to update DNS with payload [%s]: %s',
                payload, e.errmsg
            )
            return None

        return payload

    def unregister_dns(self, force: Optional[bool] = False) -> None:
        """
        Use existing kerberos ticket to remove our DNS entries.
        This is performed as part of leaving a domain (IPA or AD).
        """
        if not self._has_dns_update:
            raise NotImplementedError

        self._assert_is_active()

        config = self.config
        if not config['allow_dns_updates']:
            # DNS updates have been disabled
            return

        fqdn = self._get_fqdn()
        try:
            dns_addresses = set([x['address'] for x in self.call_sync('dnsclient.forward_lookup', {
                'names': [fqdn]
            })])
        except dns.resolver.NXDOMAIN:
            self.logger.warning(
                f'DNS lookup of {fqdn}. failed with NXDOMAIN. '
                'This may indicate that DNS entries for the TrueNAS server have '
                'already been deleted; however, it may also indicate the '
                'presence of larger underlying DNS configuration issues.'
            )
            return

        ips_in_use = set([x['address'] for x in self.call_sync('interface.ip_in_use')])
        if not dns_addresses & ips_in_use:
            # raise a CallError here because we don't want someone fat-fingering
            # input and removing an unrelated computer in the domain.
            raise CallError(
                f'DNS records indicate that {fqdn} may be associated '
                'with a different computer in the domain. Forward lookup returned the '
                f'following results: {", ".join(dns_addresses)}.'
            )

        payload = []

        for ip in dns_addresses:
            addr = ipaddress.ip_address(ip)
            payload.append({
                'command': 'DELETE',
                'name': fqdn,
                'address': str(addr),
                'type': 'A' if addr.version == 4 else 'AAAA'
            })

        try:
            self.middleware.call_sync('dns.nsupdate', {'ops': payload})
        except CallError as e:
            self.logger.warning(
                'Failed to update DNS with payload [%s]: %s',
                payload, e.err_msg
            )

    def _perm_check(self, st, expected_mode: int) -> Union[str, None]:
        """
        perform basic checks that stat security info matches expectations

        returns a string that will be appended to error messages or None
        type if no errors found
        """
        if st.st_uid != 0:
            return f'file owned by uid {st.st_uid} rather than root.'
        if st.st_gid != 0:
            return f'file owned by gid {st.st_gid} rather than root.'

        if stat.S_IMODE(st.st_mode) != expected_mode:
            return (
                f'file permissions {oct(stat.S_IMODE(st.st_mode))} '
                f'instead of expected value of {oct(expected_mode)}.'
            )

        return None

    def _health_check_krb5(self) -> None:
        """
        Individual directory services may call this within their
        `_health_check_impl()` method if the directory service uses
        kerberos.
        """
        try:
            st = os.stat('/etc/krb5.conf')
        except FileNotFoundError:
            self._faulted_reason = (
                'Kerberos configuration file is missing. This may indicate '
                'the file was accidentally deleted by a user with '
                'admin shell access to the TrueNAS server.'
            )

            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_NO_CONFIG,
                self.faulted_reason
            )

        if (err_str := self._perm_check(st, 0o644)) is not None:
            self.faulted_reason = (
                'Unexpected permissions or ownership on the kerberos '
                f'configuration file: {err_str}'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_CONFIG_PERM,
                self.faulted_reason
            )

        try:
            st = os.stat(krb5_constants.krb5ccache.SYSTEM.value)
        except FileNotFoundError:
            self.faulted_reason = (
                'System kerberos credential cache missing. This may indicate '
                'failure to renew kerberos credential or initialize a new '
                'ticket. Common reasons for this to happen are DNS resolution '
                'failures and unexpected changes to the TrueNAS server\'s host '
                'principal keytab on the IPA server that were not stored on the '
                'TrueNAS server'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_NO_CCACHE,
                self.faulted_reason
            )

        if (err_str := self._perm_check(st, 0o600)) is not None:
            self.faulted_reason = (
                'Unexpected permissions or ownership on the system kerberos '
                f'credentials cache file: {err_str} '
                'This may have allowed unautorized user to impersonate the '
                'TrueNAS server.'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_CCACHE_PERM,
                self.faulted_reason
            )

        try:
            st = os.stat(krb5_constants.KRB_Keytab.SYSTEM.value)
        except FileNotFoundError:
            self.faulted_reason = (
                'System keytab is missing. This may indicate that an administrative '
                'action was taken to remove the required IPA host principal '
                'keytab from the TrueNAS server. Rejoining IPA domain may be '
                'required in order to resolve this issue.'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_NO_KEYTAB,
                self.faulted_reason
            )

        if (err_str := self._perm_check(st, 0o600)) is not None:
            self.faulted_reason = (
                'Unexpected permissions or ownership on the IPA keberos keytab '
                f'file: {err_str} '
                'This error may have exposed the TrueNAS server\'s host principal '
                'credentials to unauthorized users. Revoking keytab and rejoining '
                'domain may be required.'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_KEYTAB_PERM,
                self.faulted_reason
            )

        if not krb5.klist_check(krb5_constants.krb5ccache.SYSTEM.value):
            self.faulted_reason = (
                'Kerberos ticket for IPA domain is expired. Failure to renew '
                'kerberos ticket may indicate issues with DNS resolution or '
                'IPA domain or realm changes that need to be accounted for '
                'in the TrueNAS configuration.'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_TKT_EXPIRED,
                self.faulted_reason
            )

    def _health_check_impl(self) -> None:
        """
        This method implements the per-directory-service health checks
        """
        raise NotImplementedError

    def health_check(self) -> bool:
        """
        Perform health checks for the directory service. This method gets
        called periodically from the alerting framework to generate health
        alerts. Error recovery is also attempted within the alert source.
        """
        if not self.is_enabled():
            self.status = DSStatus.DISABLED.name
            return False
        try:
            if self._is_enterprise:
                match self.call_sync('failover.status'):
                    case 'MASTER' | 'SINGLE':
                        # do health check on this node
                        self._health_check_impl()
                    case 'BACKUP':
                        # get health status from master
                        summary = self.call_sync(
                            'failover.call_remote',
                            'directoryservices.summary'
                        )
                        if summary['status'] == 'FAULTED':
                            self.status = DSStatus.FAULTED.name
                            self._faulted_reason = summary['satus_msg']
                            raise CallError(
                                'Active controller directory service is unhealthy'
                            )
                    case _:
                        # just lie for now and say we're healthy
                        pass
            else:
                self._health_check_impl()
        except Exception as e:
            self.status = DSStatus.FAULTED.name
            raise e from None

        self.status = DSStatus.HEALTHY.name
        return True

    def summary(self):
        raise NotImplementedError

    def is_joined(self) -> bool:
        raise NotImplementedError

    def join(self) -> dict:
        raise NotImplementedError

    def leave(self) -> dict:
        raise NotImplementedError

    def set_spn(self, spn_list: list) -> list:
        raise NotImplementedError

    def del_spn(self, spn_list: list) -> list:
        raise NotImplementedError

    def _add_sid_info_to_entries(self, nss_entries: list) -> list:
        to_remove = []
        if self.name == 'activedirectory':
            domain_info = self.call_sync('idmap.query', [], {'extra': {
                'additional_information': ['DOMAIN_INFO']
            }})
            dom_by_sid = {dom['domain_info']['sid']: dom for dom in domain_info}
        else:
            dom_by_sid = None

        idmaps = self.call_sync('idmap.convert_unixids', nss_entries)

        for idx, entry in enumerate(nss_entries):
            unixkey = f'{IDType[entry["id_type"]].wbc_str()}:{entry["id"]}'
            if unixkey not in idmaps['mapped']:
                # not all users / groups in SSSD have SIDs
                # and so we'll leave them with a null SID and
                continue

            idmap_entry = idmaps['mapped'][unixkey]
            if idmap_entry['sid'].startswith((SID_LOCAL_GROUP_PREFIX, SID_LOCAL_USER_PREFIX)):
                self.logger.warning('%s [%d] collides with local user or group. '
                                    'Omitting from cache', entry['id_type'], entry['id'])
                to_remove.append(idx)
                continue

            entry['sid'] = idmap_entry['sid']
            entry['id_type'] = idmap_entry['id_type']
            if dom_by_sid:
                entry['domain_info'] = dom_by_sid[idmap_entry['sid'].rsplit('-', 1)[0]]

        to_remove.reverse()
        for idx in to_remove:
            nss_entries.pop(idx)

        return nss_entries

    def _get_entries_for_cache(self, entry_type: str) -> list:
        """
        This generator yields batches of NSS entries as tuples containing
        100 entries. This avoids having to allocate huge amounts of memory
        to handle perhaps tens of thousands of individual users and groups
        """
        out = []
        match entry_type:
            case IDType.USER:
                nss_fn = pwd.iterpw
            case IDType.GROUP:
                nss_fn = grp.itergrp
            case _:
                raise ValueError(f'{entry_type}: unexpected `entry_type`')

        nss = nss_fn(module=self._nss_module)
        for entries in batched(nss, MAX_REQUEST_LENGTH):
            for entry in entries:
                out.append({
                    'id': entry.pw_uid if entry_type is IDType.USER else entry.gr_gid,
                    'sid': None,
                    'nss': entry,
                    'id_type': entry_type.name,
                    'domain_info': None
                })

            """
            Depending on the directory sevice we may need to add SID
            information to the NSS entries.
            """
            if not self._has_sids:
                yield out
            else:
                yield self._add_sid_info_to_entries(out)

    def fill_cache(self) -> None:
        """
        Populate our directory services cache based on NSS results from
        the domain controller / LDAP server.
        """
        if not self.config['enumerate']:
            return

        self._assert_is_active()

        user_cnt = 0
        group_cnt = 0

        for users in self._get_entries_for_cache(IDType.USER):
            for u in users:
                user_data = u['nss']
                if u['domain_info']:
                    rid = int(u['sid'].rsplit('-', 1)[1])
                    _id = 100000 + u['domain_info']['range_low'] + rid
                else:
                    _id = 100000000 + user_cnt

                entry = {
                    'id': _id,
                    'uid': user_data.pw_uid,
                    'username': user_data.pw_name,
                    'unixhash': None,
                    'smbhash': None,
                    'group': {},
                    'home': user_data.pw_dir,
                    'shell': user_data.pw_shell,
                    'full_name': user_data.pw_gecos,
                    'builtin': False,
                    'email': '',
                    'password_disabled': False,
                    'locked': False,
                    'sudo_commands': [],
                    'sudo_commands_nopasswd': False,
                    'attributes': {},
                    'groups': [],
                    'sshpubkey': None,
                    'local': False,
                    'id_type_both': u['id_type'] == 'BOTH',
                    'nt_name': user_data.pw_name,
                    'smb': u['sid'] is not None,
                    'sid': u['sid'],
                }
                self.call_sync(
                    'directoryservices.cache.insert',
                    self._name.upper(), 'USER', entry
                )
                user_cnt += 1

        for groups in self._get_entries_for_cache(IDType.GROUP):
            for g in groups:
                group_data = g['nss']
                if g['domain_info']:
                    rid = int(g['sid'].rsplit('-', 1)[1])
                    _id = 100000 + g['domain_info']['range_low'] + rid
                else:
                    _id = 100000000 + group_cnt

                entry = {
                    'id': _id,
                    'gid': group_data.gr_gid,
                    'name': group_data.gr_name,
                    'group': group_data.gr_name,
                    'builtin': False,
                    'sudo_commands': [],
                    'sudo_commands_nopasswd': [],
                    'users': [],
                    'local': False,
                    'id_type_both': g['id_type'] == 'BOTH',
                    'nt_name': group_data.gr_name,
                    'smb': g['sid'] is not None,
                    'sid': g['sid'],
                }
                self.call_sync(
                    'directoryservices.cache.insert',
                    self._name.upper(), 'GROUP', entry
                )
                group_cnt += 1
