from django.http import HttpResponseForbidden
from django.conf import settings
from .models import Tenant
from .utils import ensure_tenant_db, set_current_tenant


def _extract_tenant_code(request):
    host = request.get_host().split(':')[0]
    allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
    if allowed_hosts and host not in allowed_hosts and '*' not in allowed_hosts:
        return None

    configured_domain = getattr(settings, 'TENANT_DOMAIN', '').strip()
    if configured_domain and host.endswith(configured_domain):
        subdomain = host[: -len(configured_domain)].rstrip('.')
        if subdomain:
            return subdomain.split('.')[0].lower()

    parts = host.split('.')
    if len(parts) > 2:
        return parts[0].lower()

    return None


class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant_id = request.session.get('tenant_id')
        tenant = None

        if tenant_id:
            tenant = Tenant.objects.using('default').filter(id=tenant_id, is_active=True).first()
            if not tenant:
                request.session.pop('tenant_id', None)
                request.session.pop('tenant_alias', None)

        if not tenant:
            tenant_code = _extract_tenant_code(request)
            if tenant_code:
                tenant = Tenant.objects.using('default').filter(code__iexact=tenant_code, is_active=True).first()
                if tenant:
                    request.session['tenant_id'] = tenant.id

        if tenant:
            db_alias = ensure_tenant_db(tenant)
            set_current_tenant(tenant, db_alias)
            request.tenant = tenant
            request.tenant_db = db_alias
            request.session['tenant_alias'] = db_alias

        try:
            return self.get_response(request)
        finally:
            set_current_tenant(None, None)


class TenantAccessMiddleware:
    # Tenant-level section access flags
    SECTION_RULES = (
        ('/customers/', 'access_customers'),
        ('/inventory/', 'access_inventory'),
        ('/sales/', 'access_sales'),
        ('/reports/', 'access_reports'),
    )
    # Per-user (staff-level) access flags — same sections, different field names
    STAFF_SECTION_RULES = (
        ('/customers/', 'can_access_customers'),
        ('/inventory/', 'can_access_inventory'),
        ('/sales/',     'can_access_sales'),
        ('/reports/',   'can_access_reports'),
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return self.get_response(request)

        # 1. Tenant-level access (module enabled/disabled by superadmin)
        for prefix, flag in self.SECTION_RULES:
            if request.path.startswith(prefix) and not getattr(tenant, flag, True):
                return HttpResponseForbidden('Access denied for this section.')

        # 2. Per-user access (staff members may have restricted modules)
        if hasattr(request, 'user') and request.user.is_authenticated:
            tenant_db = getattr(request, 'tenant_db', None)
            if tenant_db:
                try:
                    from apps.accounts.models import UserProfile
                    profile = UserProfile.objects.using(tenant_db).filter(
                        user_id=request.user.id
                    ).first()
                    if profile and profile.is_staff_level:
                        for prefix, field in self.STAFF_SECTION_RULES:
                            if request.path.startswith(prefix) and not getattr(profile, field, True):
                                return HttpResponseForbidden(
                                    'You do not have permission to access this section.'
                                )
                except Exception:
                    pass  # Don't break requests on middleware errors

        return self.get_response(request)
