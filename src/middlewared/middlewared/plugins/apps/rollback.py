from middlewared.schema import accepts, Dict, List, Ref, returns, Str
from middlewared.service import job, Service, ValidationErrors

from .compose_utils import compose_action
from .ix_apps.lifecycle import add_context_to_values, get_current_app_config, update_app_config
from .ix_apps.metadata import update_app_metadata
from .ix_apps.path import get_installed_app_path, get_installed_app_version_path
from .ix_apps.rollback import clean_newer_versions, get_rollback_versions


class AppService(Service):

    class Config:
        namespace = 'app'
        cli_namespace = 'app'

    @accepts(
        Str('app_name'),
        Dict(
            'options',
            Str('app_version', empty=False, required=True),
        )
    )
    @returns(Ref('app_query'))
    @job(lock=lambda args: f'app_rollback_{args[0]}')
    def rollback(self, job, app_name, options):
        """
        Rollback `app_name` app to previous version.
        """
        app = self.middleware.call_sync('app.get_instance', app_name)
        verrors = ValidationErrors()
        if options['app_version'] == app['version']:
            verrors.add('options.app_version', 'Cannot rollback to same version')
        elif options['app_version'] not in get_rollback_versions(app_name, app['version']):
            verrors.add('options.app_version', 'Specified version is not available for rollback')

        verrors.check()

        rollback_version = self.middleware.call_sync(
            'catalog.app_version_details', get_installed_app_version_path(app_name, options['app_version'])
        )
        config = get_current_app_config(app_name, options['app_version'])
        new_values, context = self.middleware.call_sync(
            'app.schema.normalise_and_validate_values', rollback_version, config, False,
            get_installed_app_path(app_name),
        )
        new_values = add_context_to_values(app_name, new_values, rollback=True)
        update_app_config(app_name, options['app_version'], new_values)

        job.set_progress(
            20, f'Completed validation for {app_name!r} app rollback to {options["app_version"]!r} version'
        )

        # Rollback steps would be
        # 1) Config should be updated
        # 2) Compose files should be rendered
        # 3) Metadata should be updated to reflect new version
        # 4) Docker should be notified to recreate resources and to let rollback commence
        # 5) Finally update collective metadata config to reflect new version
        update_app_metadata(app_name, rollback_version)
        job.set_progress(40, f'Rolling back {app_name!r} app to {options["app_version"]!r} version')
        try:
            compose_action(app_name, options['app_version'], 'up', force_recreate=True, remove_orphans=True)
        finally:
            self.middleware.call_sync('app.metadata.generate').wait_sync(raise_error=True)
            clean_newer_versions(app_name, options['app_version'])

        job.set_progress(100, f'Rollback completed for {app_name!r} app to {options["app_version"]!r} version')

        return self.middleware.call_sync('app.get_instance', app_name)

    @accepts(Str('app_name'))
    @returns(List('rollback_versions', items=[Str('version')]))
    def rollback_versions(self, app_name):
        """
        Retrieve versions available for rollback for `app_name` app.
        """
        app = self.middleware.call_sync('app.get_instance', app_name)
        return get_rollback_versions(app_name, app['version'])
