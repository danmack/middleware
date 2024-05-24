from datetime import timedelta
import logging
from middlewared.alert.base import AlertClass, AlertCategory, Alert, AlertLevel, AlertSource
from middlewared.alert.schedule import CrontabSchedule, IntervalSchedule
from middlewared.utils.directoryservices.constants import DSType
from middlewared.utils.directoryservices.health import (
    KRB5HealthError, ADHealthError,
)
from middlewared.plugins.directoryservices_.all import get_enabled_ds
from middlewared.service_exception import CallError

log = logging.getLogger("activedirectory_check_alertmod")


class ActiveDirectoryDomainBindAlertClass(AlertClass):
    category = AlertCategory.DIRECTORY_SERVICE
    level = AlertLevel.WARNING
    title = "Active Directory Bind Is Not Healthy"
    text = "Attempt to connect to domain controller failed: %(wberr)s."


class ActiveDirectoryDomainHealthAlertClass(AlertClass):
    category = AlertCategory.DIRECTORY_SERVICE
    level = AlertLevel.WARNING
    title = "Active Directory Domain Validation Failed"
    text = "Domain validation failed with error: %(verrs)s"


class ActiveDirectoryDomainHealthAlertSource(AlertSource):
    schedule = CrontabSchedule(hour=1)
    run_on_backup_node = False

    async def check(self):
        ds_obj = await self.middleware.run_in_thread(get_enabled_ds)
        if ds_obj is None or ds_obj.ds_type is not DSType.AD:
            return

        conf = ds_obj.config
        try:
            await self.middleware.call("activedirectory.check_nameservers", conf["domainname"], conf["site"])
        except CallError as e:
            return Alert(
                ActiveDirectoryDomainHealthAlertClass,
                {'verrs': e.errmsg},
                key=None
            )


class ActiveDirectoryDomainBindAlertSource(AlertSource):
    schedule = IntervalSchedule(timedelta(minutes=10))
    run_on_backup_node = False

    async def check(self):
        ds_obj = await self.middleware.run_in_thread(get_enabled_ds)
        if ds_obj is None or ds_obj.ds_type is not DSType.AD:
            return

        try:
            await self.middleware.run_in_thread(ds_obj.health_check)
        except KRB5HealthError as e:
            # For now we can simply try to start kerberos
            # to recover from the health issue.
            #
            # This fixes permissions on files (which generates additional
            # error messages regarding type of changes made), gets a
            # fresh kerberos ticket, and sets up a transient job to
            # renew our tickets.
            self.middleware.logger.debug(
                'Attempting to recover kerberos service after health '
                'check failure for the following reason: %s',
                e.errmsg
            )
            try:
                await self.middleware.call('kerberos.start')
            except Exception:
                self.logger.warning('Failed to recover kerberos service.', exc_info=True)

            return Alert(
                ActiveDirectoryDomainBindAlertClass,
                {'wberr': str(e)},
                key=None
            )
        except ADHealthError as e:
            # Currently recovery steps are performed during actual health_check()
            # call. The only way we get here is if service is not recoverable.
            return Alert(
                ActiveDirectoryDomainBindAlertClass,
                {'wberr': str(e)},
                key=None
            )
        except Exception as e:
            # Unexpected exception type. Most likely a bug in health_check()
            self.logger.debug("Unexpected error", exc_info=True)
            return Alert(
                ActiveDirectoryDomainBindAlertClass,
                {'wberr': str(e)},
                key=None
            )
