from .base_interface import DirectoryServiceInterface
from middlewared.utils.directoryservices.constants import DSType
from middlewared.utils.nss.nss_common import NssModule


class LdapDirectoryService(DirectoryServiceInterface):
    def __init__(self, middleware, is_enterprise):
        super().__init__(
            middleware=middleware,
            ds_type=DSType.LDAP,
            datastore_name='directoryservice.ldap',
            datastore_prefix='ldap_',
            has_sids=False,
            is_enterprise=is_enterprise,
            nss_module=NssModule.SSS.name
        )

    def is_enabled(self) -> bool:
        """
        Since we're currently layered on top of ldap plugin the
        check is only for case where we're enabled and not IPA
        """
        return self.config['enable'] and self.config['server_type'] != 'FREEIPA'

    def _health_check_impl(self) -> None:
        # retrieving root DSE validates that our LDAP credentials
        # work.
        self.call_sync('ldap.get_root_DSE')

        # actual PAM / NSS integration is handled by SSSD so we
        # need to check this as well.
        if not self.call_sync('service.started', 'sssd'):
            self.call_sync('service.start', 'sssd', {'silent': False})

    def summary(self) -> dict:
        return {
           'type': self.name.upper(),
           'status': self.status.name,
           'status_msg': status_msg,
           'domain_info': None
        }
