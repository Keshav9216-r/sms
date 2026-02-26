from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

from apps.accounts.models import UserProfile
from apps.tenants.models import Tenant
from apps.tenants.utils import ensure_tenant_schema, set_current_tenant, provision_tenant_database, migrate_tenant_database


class Command(BaseCommand):
    help = 'Seed demo data for superadmin, tenant, and tenant users.'

    def add_arguments(self, parser):
        parser.add_argument('--tenant-code', default='demo-shop', help='Tenant code')
        parser.add_argument('--tenant-name', default='Demo Shop', help='Tenant name')
        parser.add_argument('--superadmin-email', default='superadmin@example.com', help='Superadmin email')
        parser.add_argument('--superadmin-password', default='superadmin123', help='Superadmin password')
        parser.add_argument('--admin-email', default='admin@demo-shop.com', help='Tenant admin email')
        parser.add_argument('--admin-password', default='admin123', help='Tenant admin password')
        parser.add_argument('--manager-password', default='', help='Manager password (defaults to admin password)')
        parser.add_argument('--cashier-password', default='', help='Cashier password (defaults to admin password)')

    def handle(self, *args, **options):
        UserModel = get_user_model()

        superadmin_email = options['superadmin_email'].lower()
        if not UserModel.objects.filter(email__iexact=superadmin_email).exists():
            superadmin = UserModel.objects.create_superuser(
                username=superadmin_email,
                email=superadmin_email,
                password=options['superadmin_password'],
            )
            UserProfile.objects.create(user=superadmin, role='superadmin')
            self.stdout.write(self.style.SUCCESS('Created superadmin user.'))
        else:
            self.stdout.write('Superadmin already exists.')

        tenant_code = options['tenant_code'].lower()
        tenant = Tenant.objects.using('default').filter(code__iexact=tenant_code).first()
        if not tenant:
            admin_email = options['admin_email'].lower()
            admin_user = UserModel.objects.create_user(
                username=admin_email,
                email=admin_email,
                password=options['admin_password'],
                is_staff=True,
            )
            tenant = Tenant.objects.create(
                name=options['tenant_name'],
                code=tenant_code,
                owner_email=admin_email,
                db_name=f"shop_{tenant_code}",
                admin_user=admin_user,
            )
            UserProfile.objects.create(user=admin_user, role='tenant_admin', tenant=tenant)

            provision_tenant_database(tenant)
            migrate_tenant_database(tenant)

            self.stdout.write(self.style.SUCCESS('Created tenant and admin user.'))
        else:
            self.stdout.write('Tenant already exists.')

        db_alias = ensure_tenant_schema(tenant)
        set_current_tenant(tenant, db_alias)

        manager_password = options['manager_password'] or options['admin_password']
        cashier_password = options['cashier_password'] or options['admin_password']

        tenant_admin_email = options['admin_email'].lower()
        if not UserModel.objects.using(db_alias).filter(email__iexact=tenant_admin_email).exists():
            tenant_admin = UserModel.objects.db_manager(db_alias).create_user(
                username=tenant_admin_email,
                email=tenant_admin_email,
                password=options['admin_password'],
                is_staff=True,
                is_superuser=True,
            )
            UserProfile.objects.using(db_alias).create(
                user=tenant_admin,
                role='tenant_admin',
                tenant_id=tenant.id,
            )

        manager_email = f"manager@{tenant_code}.com"
        if not UserModel.objects.using(db_alias).filter(email__iexact=manager_email).exists():
            manager = UserModel.objects.db_manager(db_alias).create_user(
                username=manager_email,
                email=manager_email,
                password=manager_password,
                is_staff=True,
            )
            UserProfile.objects.using(db_alias).create(
                user=manager,
                role='manager',
                tenant_id=tenant.id,
            )

        cashier_email = f"cashier@{tenant_code}.com"
        if not UserModel.objects.using(db_alias).filter(email__iexact=cashier_email).exists():
            cashier = UserModel.objects.db_manager(db_alias).create_user(
                username=cashier_email,
                email=cashier_email,
                password=cashier_password,
            )
            UserProfile.objects.using(db_alias).create(
                user=cashier,
                role='cashier',
                tenant_id=tenant.id,
            )

        set_current_tenant(None, None)
        self.stdout.write(self.style.SUCCESS('Demo tenant users seeded.'))
