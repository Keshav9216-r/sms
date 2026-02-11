from django.contrib import admin
from django.contrib import messages
from django.urls import path, reverse
from django.utils.html import format_html
from django.shortcuts import get_object_or_404, render
from .models import Tenant
from .utils import provision_tenant_database, migrate_tenant_database, ensure_tenant_db
from apps.customers.models import Customer
from apps.inventory.models import Product


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'code',
        'owner_email',
        'db_name',
        'is_active',
        'access_customers',
        'access_inventory',
        'access_sales',
        'access_reports',
        'updated_at',
        'view_data_link',
    )
    list_filter = ('is_active', 'access_customers', 'access_inventory', 'access_sales', 'access_reports')
    search_fields = ('name', 'code', 'owner_email', 'db_name')
    ordering = ('name',)
    actions = ['provision_databases']

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<int:tenant_id>/data/', self.admin_site.admin_view(self.tenant_data_view), name='tenant-data'),
        ]
        return custom_urls + urls

    def view_data_link(self, obj):
        url = reverse('admin:tenant-data', args=[obj.id])
        return format_html('<a href="{}">View</a>', url)
    view_data_link.short_description = 'Data'

    def provision_databases(self, request, queryset):
        for tenant in queryset:
            try:
                provision_tenant_database(tenant)
                migrate_tenant_database(tenant)
                self.message_user(request, f"Provisioned database for {tenant.name}")
            except Exception as exc:
                messages.error(request, f"Failed provisioning {tenant.name}: {exc}")

    provision_databases.short_description = 'Provision tenant database and migrate'

    def tenant_data_view(self, request, tenant_id):
        tenant = get_object_or_404(Tenant, id=tenant_id)
        db_alias = ensure_tenant_db(tenant)
        customers = Customer.objects.using(db_alias).all()[:200]
        products = Product.objects.using(db_alias).all()[:200]

        context = dict(
            self.admin_site.each_context(request),
            tenant=tenant,
            customers=customers,
            products=products,
        )
        return render(request, 'admin/tenants/tenant_data.html', context)
