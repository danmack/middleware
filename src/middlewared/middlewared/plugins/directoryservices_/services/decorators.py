# Decorators for directory services methods

def active_controller(fn):
    def check_is_active(*args, **kwargs):
        self = args[0]
        self._assert_is_active()
        return fn(*args, **kwargs)

    return check_is_active


def kerberos_ticket(fn):
    def check_ticket(*args, **kwargs):
        self = args[0]
        self._check_ticket()
        return fn(*args, **kwargs)

    return check_ticket
