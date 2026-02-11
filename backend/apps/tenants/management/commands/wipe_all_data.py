from django.core.management.base import BaseCommand
from django.core.management import call_command
from apps.tenants.models import Tenant
from apps.tenants.utils import ensure_tenant_db


class Command(BaseCommand):
    help = 'Wipe all data from platform and tenant databases.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--yes',
            action='store_true',
            help='Confirm destructive wipe without prompt.'
        )

    def handle(self, *args, **options):
        if not options['yes']:
            self.stdout.write(self.style.ERROR('This will delete ALL data.'))
            confirm = input('Type WIPE to continue: ').strip()
            if confirm != 'WIPE':
                self.stdout.write(self.style.WARNING('Aborted.'))
                return

        self.stdout.write('Flushing platform database...')
        call_command('flush', interactive=False)

        tenants = Tenant.objects.using('default').all()
        for tenant in tenants:
            alias = ensure_tenant_db(tenant)
            self.stdout.write(f'Flushing tenant database: {tenant.name} ({alias})')
            call_command('flush', database=alias, interactive=False)

        self.stdout.write(self.style.SUCCESS('All data wiped.'))
