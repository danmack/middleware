# Decorators for directory services methods

def active_controller(fn):
    """
    Decorator to raise a CallError if we're
    not active controller on HA (single is OK).

    _assert_is_active() is provided by the base
    directory service class.
    """
    def check_is_active(*args, **kwargs):
        self = args[0]
        self._assert_is_active()
        return fn(*args, **kwargs)

    return check_is_active


def kerberos_ticket(fn):
    """
    Decorator to raise a CallError if no ccache
    or if ticket in ccache is expired

    _assert_has_krb5_tkt() is provided by the
    kerberos mixin.
    """
    def check_ticket(*args, **kwargs):
        self = args[0]
        self._assert_has_krb5_tkt()
        return fn(*args, **kwargs)

    return check_ticket
