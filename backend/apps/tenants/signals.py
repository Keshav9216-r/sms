from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Tenant
from .utils import provision_tenant_database, migrate_tenant_database


@receiver(post_save, sender=Tenant)
def auto_provision_tenant_database(sender, instance, created, **kwargs):
    if not created or kwargs.get('raw'):
        return

    provision_tenant_database(instance)
    migrate_tenant_database(instance)
