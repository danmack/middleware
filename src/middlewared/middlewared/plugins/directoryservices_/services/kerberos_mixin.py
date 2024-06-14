import os

from middlewared.utils.directoryservices import (
    krb5, krb5_constants
)
from middlewared.utils.directoryservices.health import (
    KRB5HealthCheckFailReason, KRB5HealthError
)


class KerberosMixin:
    """
    Base directory services class. This provides common status-related code
    for directory
    """

    def set_spn(self, spn_list: list) -> list:
        """
        Set kerberos service principal. Implementation varies based on
        type of service (AD, IPA, LDAP, etc)
        """
        raise NotImplementedError

    def del_spn(self, spn_list: list) -> list:
        """
        Delete kerberos service principal. Implementation varies based on
        type of service (AD, IPA, LDAP, etc)
        """
        raise NotImplementedError

    def _assert_has_krb5_tkt(self) -> None:
        """
        check_ticket() raises a CallError if ccache is missing or ticket is
        expired

        This method is called by the @keberos_ticket decorator
        """
        krb5.check_ticket(krb5.krb5_constants.krb5ccache.SYSTEM.value)

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
            self._faulted_reason = (
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
            self._faulted_reason = (
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
            self._faulted_reason = (
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
            self._faulted_reason = (
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
            self._faulted_reason = (
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
            self._faulted_reason = (
                'Kerberos ticket for IPA domain is expired. Failure to renew '
                'kerberos ticket may indicate issues with DNS resolution or '
                'IPA domain or realm changes that need to be accounted for '
                'in the TrueNAS configuration.'
            )
            raise KRB5HealthError(
                KRB5HealthCheckFailReason.KRB5_TKT_EXPIRED,
                self.faulted_reason
            )
