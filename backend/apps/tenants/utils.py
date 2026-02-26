import os
import re
import threading
from django.conf import settings
from django.core.management import call_command
from django.db import connections

_local = threading.local()


def set_current_tenant(tenant=None, db_alias=None):
    _local.tenant = tenant
    _local.db_alias = db_alias


def get_current_tenant():
    return getattr(_local, 'tenant', None)


def get_current_tenant_db():
    return getattr(_local, 'db_alias', None)


def _safe_tenant_db_filename(raw_name, tenant_id):
    candidate = os.path.basename((raw_name or '').strip()).replace('\x00', '')
    if not candidate or not re.fullmatch(r'[A-Za-z0-9._-]{1,100}', candidate):
        candidate = f"tenant_{tenant_id}"
    if not candidate.endswith('.sqlite3'):
        candidate = f"{candidate}.sqlite3"
    return candidate


def build_tenant_db_config(tenant):
    base_config = settings.DATABASES.get('default', {}).copy()
    tenant_db_dir = getattr(settings, 'TENANT_DB_DIR', None)
    if not tenant_db_dir:
        tenant_db_dir = os.path.join(settings.BASE_DIR, 'tenant_dbs')
    tenant_db_dir = os.path.abspath(tenant_db_dir)
    os.makedirs(tenant_db_dir, exist_ok=True)
    db_filename = _safe_tenant_db_filename(tenant.db_name, tenant.id)
    db_path = os.path.abspath(os.path.join(tenant_db_dir, db_filename))
    if not db_path.startswith(f"{tenant_db_dir}{os.sep}"):
        raise ValueError("Invalid tenant database path.")
    base_config.update(
        {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': db_path,
        }
    )
    base_config.setdefault('ATOMIC_REQUESTS', False)
    base_config.setdefault('AUTOCOMMIT', True)
    base_config.setdefault('CONN_HEALTH_CHECKS', False)
    base_config.setdefault('TIME_ZONE', settings.TIME_ZONE)
    return base_config


def ensure_tenant_db(tenant):
    alias = f"tenant_{tenant.id}"
    if alias not in settings.DATABASES:
        settings.DATABASES[alias] = build_tenant_db_config(tenant)
    if alias not in connections.databases:
        connections.databases[alias] = settings.DATABASES[alias]
    return alias


def _get_admin_db_config():
    return {
        'dbname': settings.POSTGRES_ADMIN_DB,
        'user': settings.POSTGRES_ADMIN_USER,
        'password': settings.POSTGRES_ADMIN_PASSWORD,
        'host': settings.POSTGRES_ADMIN_HOST,
        'port': settings.POSTGRES_ADMIN_PORT,
    }


def provision_tenant_database(tenant):
    db_config = build_tenant_db_config(tenant)
    db_path = db_config.get('NAME')
    if db_path:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        if not os.path.exists(db_path):
            open(db_path, 'a').close()
        os.chmod(db_path, 0o600)
    return


def delete_tenant_database(tenant):
    db_config = build_tenant_db_config(tenant)
    db_path = db_config.get('NAME')
    if db_path and os.path.exists(db_path):
        os.remove(db_path)


def migrate_tenant_database(tenant):
    alias = ensure_tenant_db(tenant)
    call_command('migrate', database=alias, interactive=False)


def ensure_tenant_schema(tenant):
    alias = ensure_tenant_db(tenant)
    connection = connections[alias]
    try:
        tables = connection.introspection.table_names()
    except Exception:
        tables = []
    if 'auth_user' not in tables:
        call_command('migrate', database=alias, interactive=False)
    return alias
