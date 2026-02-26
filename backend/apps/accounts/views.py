import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.views.decorators.http import require_POST
from .models import UserProfile, ChangeLog
from apps.tenants.models import Tenant
from apps.tenants.utils import set_current_tenant, ensure_tenant_schema

logger = logging.getLogger('security')

User = get_user_model()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_tenant_profile(request):
    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db or not request.user.is_authenticated:
        return None
    return UserProfile.objects.using(tenant_db).filter(user_id=request.user.id).first()


def is_staff_level(request):
    """True if the logged-in user is a staff/cashier (restricted role)."""
    profile = _get_tenant_profile(request)
    return bool(profile and profile.is_staff_level)


def can_manage_staff(request):
    """True if the user is tenant_admin or manager."""
    profile = _get_tenant_profile(request)
    return bool(profile and profile.role in ('tenant_admin', 'manager'))


def log_change(request, action, model_name, record_id, description, before=None, after=None):
    """Write an entry to the ChangeLog in the tenant DB."""
    import json
    tenant_db = getattr(request, 'tenant_db', None)
    if tenant_db and request.user.is_authenticated:
        try:
            ChangeLog.objects.using(tenant_db).create(
                username=request.user.username,
                action=action,
                model_name=model_name,
                record_id=str(record_id),
                description=description,
                before_data=json.dumps(before) if before else '',
                after_data=json.dumps(after) if after else '',
            )
        except Exception:
            logger.exception("Failed to write ChangeLog entry for action '%s'", action)


# ─── Authentication ────────────────────────────────────────────────────────────

def _handle_login(request, template_name, allow_superadmin=False, allow_vendor_owner_lookup=False):
    if request.method == 'POST':
        identifier = (request.POST.get('identifier') or '').strip().lower()
        password = request.POST.get('password') or ''

        original_tenant = getattr(request, 'tenant', None)
        original_db_alias = getattr(request, 'tenant_db', None)

        set_current_tenant(None, None)
        user = authenticate(request, username=identifier, password=password)

        if user:
            profile = UserProfile.objects.using('default').filter(user_id=user.id).first()
            if profile and profile.role == 'superadmin':
                if allow_superadmin:
                    user.backend = 'django.contrib.auth.backends.ModelBackend'
                    login(request, user)
                    request.session.cycle_key()
                    request.session.pop('tenant_id', None)
                    request.session.pop('tenant_alias', None)
                    logger.info("Superadmin '%s' logged in.", identifier)
                    return redirect('superadmin_dashboard')
                messages.error(request, 'Please use the superadmin login page.')
                return render(request, template_name)

        # Superadmin login page must not fall through to vendor/tenant auth
        if allow_superadmin:
            messages.error(request, 'Invalid credentials or unauthorized access.')
            return render(request, template_name)

        if original_tenant and original_db_alias:
            set_current_tenant(original_tenant, original_db_alias)

        tenant = getattr(request, 'tenant', None)
        if tenant:
            db_alias = ensure_tenant_schema(tenant)
            set_current_tenant(tenant, db_alias)
            try:
                user = authenticate(request, username=identifier, password=password)
                if user:
                    set_current_tenant(None, None)
                    user.backend = 'apps.tenants.auth_backends.TenantModelBackend'
                    login(request, user)
                    request.session.cycle_key()
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
                    logger.info("User '%s' logged into tenant '%s'.", identifier, tenant.code)
                    return redirect('dashboard')
            finally:
                set_current_tenant(None, None)

        tenant = Tenant.objects.using('default').filter(code__iexact=identifier, is_active=True).first()
        if not tenant and allow_vendor_owner_lookup:
            tenant = Tenant.objects.using('default').filter(owner_email__iexact=identifier, is_active=True).first()
        if tenant and tenant.admin_user:
            db_alias = ensure_tenant_schema(tenant)
            set_current_tenant(tenant, db_alias)
            try:
                lookup_email = tenant.admin_user.email if tenant.admin_user else tenant.owner_email
                user = User.objects.using(db_alias).filter(email__iexact=lookup_email).first()
                if user and user.check_password(password):
                    set_current_tenant(None, None)
                    user.backend = 'apps.tenants.auth_backends.TenantModelBackend'
                    login(request, user)
                    request.session.cycle_key()
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
                    logger.info("Vendor admin '%s' logged into tenant '%s'.", identifier, tenant.code)
                    return redirect('dashboard')

                if not user and tenant.admin_user.check_password(password):
                    logger.warning(
                        "Vendor admin user missing in tenant DB for tenant '%s' (email=%s).",
                        tenant.code, lookup_email,
                    )
                    messages.error(request, 'Account setup is incomplete. Please contact the administrator.')
                    return render(request, template_name)
            finally:
                set_current_tenant(None, None)

        messages.error(request, 'Invalid credentials or unauthorized access.')
        return render(request, template_name)

    return render(request, template_name)


def login_view(request):
    return render(request, 'accounts/login_choice.html')


def vendor_login_view(request):
    return _handle_login(
        request,
        'accounts/vendor_login.html',
        allow_superadmin=False,
        allow_vendor_owner_lookup=True,
    )


def staff_login_view(request):
    """Staff login: shop_code + username + password."""
    if request.method == 'POST':
        shop_code = (request.POST.get('shop_code') or '').strip().lower()
        username  = (request.POST.get('username') or '').strip()
        password  = request.POST.get('password') or ''

        if not shop_code:
            messages.error(request, 'Shop code is required.')
            return render(request, 'accounts/user_login.html')

        tenant = Tenant.objects.using('default').filter(code__iexact=shop_code, is_active=True).first()
        if not tenant:
            messages.error(request, 'Invalid shop code.')
            return render(request, 'accounts/user_login.html')

        db_alias = ensure_tenant_schema(tenant)
        set_current_tenant(tenant, db_alias)
        try:
            user = authenticate(request, username=username, password=password)
            if user:
                profile = UserProfile.objects.using(db_alias).filter(user_id=user.id).first()
                if profile and profile.role == 'superadmin':
                    messages.error(request, 'Please use the appropriate login page.')
                    return render(request, 'accounts/user_login.html')
                set_current_tenant(None, None)
                user.backend = 'apps.tenants.auth_backends.TenantModelBackend'
                login(request, user)
                request.session.cycle_key()
                request.session['tenant_id'] = tenant.id
                request.session['tenant_alias'] = db_alias
                logger.info("Staff '%s' logged into tenant '%s'.", username, tenant.code)
                return redirect('dashboard')
        finally:
            set_current_tenant(None, None)

        messages.error(request, 'Invalid credentials. Check shop code, username, and password.')
        return render(request, 'accounts/user_login.html')

    return render(request, 'accounts/user_login.html')


def user_login_view(request):
    return staff_login_view(request)


def superadmin_login_view(request):
    return _handle_login(request, 'accounts/superadmin_login.html', allow_superadmin=True)


@require_POST
def logout_view(request):
    logger.info("User '%s' logged out.", request.user.username if request.user.is_authenticated else 'anonymous')
    logout(request)
    request.session.pop('tenant_id', None)
    request.session.pop('tenant_alias', None)
    return redirect('login')


# ─── Dashboard ────────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    user_profile, _ = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={
            'role': 'cashier',
            'tenant': getattr(request, 'tenant', None),
        },
    )

    from apps.inventory.models import Product, Inventory
    from apps.sales.models import Sale
    from apps.customers.models import Customer
    from django.utils import timezone
    from django.db.models import F, Sum

    tenant_db = getattr(request, 'tenant_db', None)
    if tenant_db:
        total_products  = Product.objects.using(tenant_db).count()
        low_stock_count = Inventory.objects.using(tenant_db).filter(
            quantity_in_stock__lte=F('product__reorder_level')
        ).count()
        total_customers = Customer.objects.using(tenant_db).count()
        today_sales = (
            Sale.objects.using(tenant_db)
            .filter(
                sale_date__date=timezone.now().date(),
                order_status='completed',
            )
            .aggregate(total=Sum('total_amount'))['total'] or 0
        )
    else:
        total_products = low_stock_count = total_customers = today_sales = 0

    return render(request, 'reports/dashboard.html', {
        'user_profile': user_profile,
        'total_products': total_products,
        'low_stock_count': low_stock_count,
        'total_customers': total_customers,
        'today_sales': today_sales,
    })


# ─── Profile ──────────────────────────────────────────────────────────────────

@login_required
def profile(request):
    user_profile, _ = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={
            'role': 'cashier',
            'tenant': getattr(request, 'tenant', None),
        },
    )

    vendor = None
    tenant_id = request.session.get('tenant_id')
    if tenant_id:
        vendor = Tenant.objects.using('default').filter(id=tenant_id).first()
    if vendor is None:
        vendor = getattr(request, 'tenant', None)

    if request.method == 'POST':
        form_type = request.POST.get('form_type', 'personal')

        if form_type == 'qr_upload':
            if user_profile.role == 'tenant_admin' and vendor:
                qr_file = request.FILES.get('qr_code')
                remove_qr = request.POST.get('remove_qr')
                if remove_qr and vendor.qr_code:
                    vendor.qr_code.delete(save=False)
                    vendor.qr_code = None
                    vendor.save(using='default')
                    messages.success(request, 'QR code removed.')
                elif qr_file:
                    if vendor.qr_code:
                        vendor.qr_code.delete(save=False)
                    vendor.qr_code = qr_file
                    vendor.save(using='default')
                    messages.success(request, 'QR code updated successfully.')
                else:
                    messages.error(request, 'No file selected.')
            else:
                messages.error(request, 'Only vendor admins can upload a QR code.')
        else:
            user_profile.phone   = request.POST.get('phone', '').strip()
            user_profile.address = request.POST.get('address', '').strip()
            user_profile.city    = request.POST.get('city', '').strip()
            user_profile.save()
            messages.success(request, 'Profile updated successfully.')
        return redirect('profile')

    return render(request, 'accounts/profile.html', {
        'profile': user_profile,
        'vendor': vendor,
    })


@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '').strip()
        new_password     = request.POST.get('new_password', '').strip()
        new_password2    = request.POST.get('new_password2', '').strip()

        if not all([current_password, new_password, new_password2]):
            messages.error(request, 'All fields are required.')
            return redirect('change_password')

        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('change_password')

        if new_password != new_password2:
            messages.error(request, 'New passwords do not match.')
            return redirect('change_password')

        try:
            validate_password(new_password, user=request.user)
        except ValidationError as exc:
            for msg in exc.messages:
                messages.error(request, msg)
            return redirect('change_password')

        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)
        logger.info("User '%s' changed their password.", request.user.username)
        messages.success(request, 'Password changed successfully.')
        return redirect('profile')

    return render(request, 'accounts/change_password.html')


# ─── Staff management ─────────────────────────────────────────────────────────

@login_required
def staff_list(request):
    if not can_manage_staff(request):
        messages.error(request, 'Only admins and managers can manage staff.')
        return redirect('dashboard')

    tenant_db = getattr(request, 'tenant_db', None)
    staff_profiles = []
    if tenant_db:
        staff_profiles = (
            UserProfile.objects.using(tenant_db)
            .select_related('user')
            .exclude(role__in=('superadmin', 'tenant_admin'))
            .order_by('role', 'user__username')
        )

    return render(request, 'accounts/staff_list.html', {'staff_profiles': staff_profiles})


@login_required
def staff_create(request):
    if not can_manage_staff(request):
        messages.error(request, 'Only admins and managers can create staff.')
        return redirect('dashboard')

    tenant_db = getattr(request, 'tenant_db', None)
    tenant    = getattr(request, 'tenant', None)
    if not tenant_db:
        messages.error(request, 'No tenant context.')
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        role     = request.POST.get('role', 'cashier')

        can_inventory = bool(request.POST.get('can_access_inventory'))
        can_sales     = bool(request.POST.get('can_access_sales'))
        can_customers = bool(request.POST.get('can_access_customers'))
        can_reports   = bool(request.POST.get('can_access_reports'))

        if role not in ('cashier', 'staff', 'manager'):
            messages.error(request, 'Invalid role.')
            return render(request, 'accounts/staff_create.html', {'tenant': tenant})

        if not username:
            messages.error(request, 'Username is required.')
            return render(request, 'accounts/staff_create.html', {'tenant': tenant})

        if User.objects.using(tenant_db).filter(username__iexact=username).exists():
            messages.error(request, f'Username "{username}" is already taken.')
            return render(request, 'accounts/staff_create.html', {'tenant': tenant})

        try:
            validate_password(password)
        except ValidationError as exc:
            for msg in exc.messages:
                messages.error(request, msg)
            return render(request, 'accounts/staff_create.html', {'tenant': tenant})

        new_user = User(username=username)
        new_user.set_password(password)
        new_user.save(using=tenant_db)

        UserProfile.objects.using(tenant_db).create(
            user=new_user,
            role=role,
            can_access_inventory=can_inventory,
            can_access_sales=can_sales,
            can_access_customers=can_customers,
            can_access_reports=can_reports,
        )
        log_change(request, 'create', 'Staff', username,
                   f'Created staff account "{username}" with role {role}.')
        messages.success(request, f'Staff account "{username}" created.')
        return redirect('staff_list')

    return render(request, 'accounts/staff_create.html', {'tenant': tenant})


@login_required
def staff_edit(request, user_id):
    if not can_manage_staff(request):
        messages.error(request, 'Only admins and managers can edit staff.')
        return redirect('dashboard')

    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db:
        return redirect('dashboard')

    target_user    = get_object_or_404(User.objects.using(tenant_db), id=user_id)
    target_profile = get_object_or_404(UserProfile.objects.using(tenant_db), user=target_user)

    if target_user == request.user or target_profile.role == 'tenant_admin':
        messages.error(request, 'Cannot edit this account here.')
        return redirect('staff_list')

    if request.method == 'POST':
        role = request.POST.get('role', target_profile.role)
        if role not in ('cashier', 'staff', 'manager'):
            messages.error(request, 'Invalid role.')
        else:
            before = {
                'role': target_profile.role,
                'is_active': target_profile.is_active,
                'can_access_inventory': target_profile.can_access_inventory,
                'can_access_sales': target_profile.can_access_sales,
                'can_access_customers': target_profile.can_access_customers,
                'can_access_reports': target_profile.can_access_reports,
            }
            target_profile.role               = role
            target_profile.can_access_inventory = bool(request.POST.get('can_access_inventory'))
            target_profile.can_access_sales     = bool(request.POST.get('can_access_sales'))
            target_profile.can_access_customers = bool(request.POST.get('can_access_customers'))
            target_profile.can_access_reports   = bool(request.POST.get('can_access_reports'))
            target_profile.is_active            = bool(request.POST.get('is_active'))
            target_profile.save(using=tenant_db)
            after = {
                'role': target_profile.role,
                'is_active': target_profile.is_active,
                'can_access_inventory': target_profile.can_access_inventory,
                'can_access_sales': target_profile.can_access_sales,
                'can_access_customers': target_profile.can_access_customers,
                'can_access_reports': target_profile.can_access_reports,
            }

            new_password = request.POST.get('new_password', '').strip()
            if new_password:
                try:
                    validate_password(new_password, user=target_user)
                    target_user.set_password(new_password)
                    target_user.save(using=tenant_db)
                except ValidationError as exc:
                    for msg in exc.messages:
                        messages.error(request, msg)
                    return render(request, 'accounts/staff_edit.html', {
                        'target_user': target_user,
                        'target_profile': target_profile,
                    })

            log_change(request, 'update', 'Staff', target_user.username,
                       f'Updated staff account "{target_user.username}" — role: {role}.',
                       before=before, after=after)
            messages.success(request, f'Staff account "{target_user.username}" updated.')
            return redirect('staff_list')

    return render(request, 'accounts/staff_edit.html', {
        'target_user': target_user,
        'target_profile': target_profile,
    })


@login_required
def staff_delete(request, user_id):
    if not can_manage_staff(request):
        messages.error(request, 'Only admins and managers can delete staff.')
        return redirect('dashboard')

    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db:
        return redirect('dashboard')

    target_user    = get_object_or_404(User.objects.using(tenant_db), id=user_id)
    target_profile = UserProfile.objects.using(tenant_db).filter(user=target_user).first()

    if target_user == request.user or (target_profile and target_profile.role == 'tenant_admin'):
        messages.error(request, 'Cannot delete this account.')
        return redirect('staff_list')

    if request.method == 'POST':
        username = target_user.username
        target_user.delete(using=tenant_db)
        log_change(request, 'delete', 'Staff', username, f'Deleted staff account "{username}".')
        messages.success(request, f'Staff account "{username}" deleted.')
        return redirect('staff_list')

    return render(request, 'accounts/staff_delete.html', {
        'target_user': target_user,
        'target_profile': target_profile,
    })


# ─── Changelog ────────────────────────────────────────────────────────────────

def _diff_data(before, after):
    """Return list of changed fields as {'field', 'before', 'after'} dicts."""
    all_keys = sorted(set(list(before.keys()) + list(after.keys())))
    return [
        {'field': k, 'before': str(before.get(k, '')), 'after': str(after.get(k, ''))}
        for k in all_keys
        if str(before.get(k, '')) != str(after.get(k, ''))
    ]


@login_required
def changelog_list(request):
    import json
    if not can_manage_staff(request):
        messages.error(request, 'Only admins and managers can view the changelog.')
        return redirect('dashboard')

    # Password verification gate — verified once per session
    if not request.session.get('changelog_verified'):
        error = None
        if request.method == 'POST' and 'verify_password' in request.POST:
            password = request.POST.get('password', '')
            if request.user.check_password(password):
                request.session['changelog_verified'] = True
                return redirect('changelog_list')
            error = 'Incorrect password. Please try again.'
        return render(request, 'accounts/changelog_verify.html', {'error': error})

    tenant_db = getattr(request, 'tenant_db', None)
    logs = []
    if tenant_db:
        for log in ChangeLog.objects.using(tenant_db).order_by('-timestamp')[:500]:
            before = json.loads(log.before_data) if log.before_data else {}
            after  = json.loads(log.after_data)  if log.after_data  else {}
            logs.append({
                'log': log,
                'before': before,
                'after': after,
                'diff': _diff_data(before, after),
            })

    return render(request, 'accounts/changelog.html', {'logs': logs})
