from .utils import get_current_tenant_db


class TenantDatabaseRouter:
    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'tenants':
            return 'default'
        tenant_db = get_current_tenant_db()
        return tenant_db or None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'tenants':
            return 'default'
        tenant_db = get_current_tenant_db()
        return tenant_db or None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db and obj2._state.db:
            return obj1._state.db == obj2._state.db
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in {'tenants', 'accounts'}:
            return True
        if app_label in {'auth', 'admin', 'contenttypes', 'sessions'}:
            return True
        return db != 'default'
