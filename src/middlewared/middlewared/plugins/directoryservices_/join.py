from .activedirectory_join_mixin import ADJoinMixin
from .ipa_join_mixin import IPAJoinMixin
from middlewared.job import Job
from middlewared.plugins.ldap_.constants import SERVER_TYPE_FREEIPA
from middlewared.service import job, Service
from middlewared.service_exception import CallError
from middlewared.utils.directoryservices.constants import DomainJoinResponse, DSType
from middlewared.utils.directoryservices.krb5 import kerberos_ticket


class DomainHealth(
    Service,
    ADJoinMixin,
    IPAJoinMixin,
):

    class Config:
        namespace = 'directoryservices.connection'
        cli_private = True
        private = True

    def _get_enabled_ds(self):
        ad = self.middleware.call_sync('datastore.config', 'directoryservice.activedirectory')
        if ad['ad_enable']:
            return DSType.AD

        ldap = self.middleware.call_sync('datastore.config', 'directoryservice.ldap')
        if ldap['ldap_enable'] is False:
            return None

        return DSType.IPA if ldap['ldap_server_type'] == SERVER_TYPE_FREEIPA else DSType.LDAP

    def activate(self) -> int:
        """ Generate etc files and start services, then start cache fill job and return job id """
        match (enabled_ds := self._get_enabled_ds()):
            case None:
                return
            case DSType.IPA:
                self._ipa_activate()
            case DSType.AD:
                self._ad_activate()
            case DSType.LDAP:
                self._ldap_activate()
            case _:
                raise ValueError(f'{enabled_ds}: unknown directory service')

        return self.middleware.call_sync('directoryservices.cache.refresh_impl').id

    @kerberos_ticket
    def _test_is_joined(self, ds_type: DSType, domain: str) -> bool:
        """ Test to see whether TrueNAS is already joined to the domain

        Args:
            ds_type: Type of directory service that is being tested. Choices
                are DSType.AD and DSType.IPA
            domain: Name of domain to be joined. For AD domains this should
                be the pre-win2k domain, and for IPA domains the kerberos
                realm.

        Returns:
            True - joined to domain
            False - not joined to domain

        Raises:
            CallError
            TypeError
        """
        if not isinstance(ds_type, DSType):
            raise TypeError(f'{type(ds_type)}: DSType is required')

        match ds_type:
            case DSType.AD:
                is_joined_fn = self._ad_test_join
            case DSType.IPA:
                is_joined_fn = self._ipa_test_join
            case _:
                raise CallError(
                    f'{ds_type}: specified directory service type does not '
                    'support domain join functionality.'
                )

        return is_joined_fn(ds_type, domain)

    @job(lock="directoryservices_join_leave")
    @kerberos_ticket
    def join_domain(self, job: Job, ds_type_str: str, domain: str, force: bool = False) -> None:
        """ Join an IPA or active directory domain

        Create TrueNAS account on remote domain controller (DC) and clean
        update TrueNAS configuration to reflect settings determined during
        the join process. Requires a valid kerberos ticket for a privileged
        account on the domain because we performing operations on the DC.

        If join fails then TrueNAS will attempt to roll back changes to a
        clean state.

        Args:
            ds_type_str: String value of the DSType to be joined. Supported
                values are 'ACTIVEDIRECTORY' and 'IPA'
            domain: Name of domain to be joined. For AD domains this should
                be the pre-win2k domain, and for IPA domains the kerberos
                realm.
            force: Skip the step where we check whether TrueNAS is already
                joined to the domain. Join should not be forced without very
                good reason as this will cause auditing events on the domain
                controller and may disrupt services on the TrueNAS server.

        Returns:
            None

        Raises:
            ValueError - ds_type_str is an invalid DSType
        """

        ds_type = DSType(ds_type_str)

        if not force:
            if self._test_is_joined(ds_type, domain):
                self.logger.debug(
                    '%s: server is already joined to domain %s',
                    ds_type_str, domain
                )
                return DomainJoinResponse.ALREADY_JOINED.value

        match ds_type:
            case DSType.AD:
                do_join_fn = self._ad_join
            case DSType.IPA:
                do_join_fn = self._ipa_join
            case _:
                raise CallError(
                    f'{ds_type}: specified directory service type does not '
                    'support domain join functionality.'
                )

        do_join_fn(job, ds_type, domain)
        return DomainJoinResponse.PERFORMED_JOIN.value

    def grant_privileges(self, ds_type_str: str, domain: str) -> None:
        ds_type = DSType(ds_type_str)

        if not self._test_is_joined(ds_type, domain):
            raise CallError('TrueNAS is not joined to domain')

        match ds_type:
            case DSType.AD:
                self._ad_grant_privileges()
            case DSType.IPA:
                self._ipa_grant_privileges()
            case _:
                raise ValueError(f'{ds_type}: unexpected directory sevice type')

    @job(lock="directoryservices_join_leave")
    @kerberos_ticket
    def leave_domain(self, job: Job, ds_type_str: str, domain: str) -> None:
        """ Leave an IPA or active directory domain

        Remove TrueNAS configuration from remote domain controller (DC) and clean
        up local configuration. Requires a valid kerberos ticket for a privileged
        account on the domain because we performing operations on the DC.

        Args:
            ds_type_str: String value of the DSType to be left. Supported
                values are 'ACTIVEDIRECTORY' and 'IPA'
            domain: Name of domain to be left. For AD domains this should
                be the pre-win2k domain, and for IPA domains the kerberos
                realm.

        Returns:
            None

        Raises:
            ValueError - ds_type_str is an invalid DSType
        """

        ds_type = DSType(ds_type_str)

        match ds_type:
            case DSType.AD:
                do_leave_fn = self._ad_leave
            case DSType.IPA:
                do_leave_fn = self._ipa_leave
            case _:
                raise CallError(
                    f'{ds_type}: specified directory service type does not '
                    'support domain join functionality.'
                )

        # Only make actual attempt to leave the domain if we have a valid join
        if self._test_is_joined(ds_type, domain):
            do_leave_fn(job, ds_type, domain)
        else:
            self.logger.warning(
                '%s: domain join is not healthy. Manual cleanup of machine account on '
                'remote domain controller for domain may be required.', domain
            )

        # TODO move cleanup methods here
