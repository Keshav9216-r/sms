import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from .models import UserProfile, UserEditLog
from apps.tenants.models import Tenant
from apps.tenants.utils import set_current_tenant, ensure_tenant_schema

logger = logging.getLogger('security')

# ──────────────────────────────────────────────────────────────────────────────
# Shared login helper (used by vendor & superadmin login)
# ──────────────────────────────────────────────────────────────────────────────

def _handle_login(request, template_name, allow_superadmin=False, allow_vendor_owner_lookup=False):
    if request.method == 'POST':
        identifier = (request.POST.get('identifier') or '').strip().lower()
        password = request.POST.get('password') or ''

        original_tenant = getattr(request, 'tenant', None)
        original_db_alias = getattr(request, 'tenant_db', None)

        # First, try to authenticate as superadmin on main database
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

        if original_tenant and original_db_alias:
            set_current_tenant(original_tenant, original_db_alias)

        # Try authenticate as tenant user
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
                UserModel = get_user_model()
                lookup_email = tenant.admin_user.email if tenant.admin_user else tenant.owner_email
                user = UserModel.objects.using(db_alias).filter(email__iexact=lookup_email).first()
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
                        "Vendor admin user missing in tenant DB for tenant '%s' (email=%s). "
                        "Tenant DB provisioning may be incomplete.",
                        tenant.code, lookup_email,
                    )
                    messages.error(request, 'Account setup is incomplete. Please contact the administrator.')
                    return render(request, template_name)
            finally:
                set_current_tenant(None, None)

        messages.error(request, 'Invalid credentials or unauthorized access.')
        return render(request, template_name)

    return render(request, template_name)


# ──────────────────────────────────────────────────────────────────────────────
# Login views
# ──────────────────────────────────────────────────────────────────────────────

def login_view(request):
    return render(request, 'accounts/login_choice.html')


def vendor_login_view(request):
    return _handle_login(
        request,
        'accounts/vendor_login.html',
        allow_superadmin=False,
        allow_vendor_owner_lookup=True,
    )


@ensure_csrf_cookie
def user_login_view(request):
    """
    Staff user login: requires Shop Code + Username + Password.
    The shop code identifies the tenant; the user is then authenticated
    against that tenant's isolated database.
    """
    if request.method != 'POST':
        return render(request, 'accounts/user_login.html')

    shop_code = (request.POST.get('shop_code') or '').strip().lower()
    username  = (request.POST.get('username')  or '').strip()
    password  =  request.POST.get('password')  or ''

    if not shop_code or not username or not password:
        messages.error(request, 'Shop code, username, and password are all required.')
        return render(request, 'accounts/user_login.html')

    # Resolve tenant from shop code
    tenant = Tenant.objects.using('default').filter(code__iexact=shop_code, is_active=True).first()
    if not tenant:
        messages.error(request, 'Shop code not found or shop is inactive.')
        return render(request, 'accounts/user_login.html')

    db_alias = ensure_tenant_schema(tenant)
    set_current_tenant(tenant, db_alias)
    try:
        # Store tenant in session so TenantModelBackend can verify it
        request.session['tenant_id'] = tenant.id
        request.session['tenant_alias'] = db_alias

        user = authenticate(request, username=username, password=password)
        if not user:
            messages.error(request, 'Invalid username or password.')
            return render(request, 'accounts/user_login.html')

        # Fetch the user's profile from the tenant DB
        profile = UserProfile.objects.using(db_alias).filter(user=user).first()

        # Reject superadmins on this login screen
        if profile and profile.role == 'superadmin':
            messages.error(request, 'Please use the superadmin login page.')
            return render(request, 'accounts/user_login.html')

        # Reject deactivated staff
        if profile and not profile.is_active:
            logger.warning("Deactivated user '%s' attempted login on tenant '%s'.", username, shop_code)
            messages.error(request, 'Your account has been deactivated. Contact your shop admin.')
            return render(request, 'accounts/user_login.html')

        set_current_tenant(None, None)
        user.backend = 'apps.tenants.auth_backends.TenantModelBackend'
        login(request, user)
        request.session.cycle_key()
        request.session['tenant_id'] = tenant.id
        request.session['tenant_alias'] = db_alias
        logger.info("Staff user '%s' logged into tenant '%s'.", username, shop_code)
        return redirect('dashboard')

    finally:
        set_current_tenant(None, None)


def superadmin_login_view(request):
    return _handle_login(request, 'accounts/superadmin_login.html', allow_superadmin=True)


def logout_view(request):
    logger.info("User '%s' logged out.", request.user.username if request.user.is_authenticated else 'anonymous')
    logout(request)
    request.session.pop('tenant_id', None)
    request.session.pop('tenant_alias', None)
    return redirect('login')


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    """Dashboard for vendor users"""
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
    from django.db.models import F

    tenant_db = getattr(request, 'tenant_db', None)
    if tenant_db:
        total_products = Product.objects.using(tenant_db).count()
        low_stock_items = Inventory.objects.using(tenant_db).filter(
            quantity_in_stock__lte=F('product__reorder_level')
        ).count()
        total_customers = Customer.objects.using(tenant_db).count()
        today_sales = Sale.objects.using(tenant_db).filter(
            sale_date__date=timezone.now().date()
        ).count()
    else:
        total_products = low_stock_items = total_customers = today_sales = 0

    context = {
        'user_profile': user_profile,
        'total_products': total_products,
        'low_stock_items': low_stock_items,
        'total_customers': total_customers,
        'today_sales': today_sales,
    }
    return render(request, 'reports/dashboard.html', context)


# ──────────────────────────────────────────────────────────────────────────────
# Profile & password
# ──────────────────────────────────────────────────────────────────────────────

@login_required
def profile(request):
    """User profile management"""
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

    qr_audit_logs = []
    if vendor:
        qr_audit_logs = (
            UserEditLog.objects.using('default')
            .filter(target_username=f"vendor:{vendor.code}", changes__startswith='[QR]')
            .order_by('-timestamp')[:10]
        )

    if request.method == 'POST':
        form_type = request.POST.get('form_type', 'personal')

        if form_type == 'qr' and vendor:
            is_vendor_owner = (
                user_profile.role == 'tenant_admin'
                and vendor.admin_user_id == request.user.id
            )
            if not is_vendor_owner:
                messages.error(request, 'Only the vendor account can manage the QR code.')
                return redirect('profile')
            forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip_address = (
                forwarded_for.split(',')[0].strip()
                if forwarded_for
                else request.META.get('REMOTE_ADDR', '')
            ) or '-'
            if request.POST.get('remove_qr'):
                old_name = vendor.qr_image.name if vendor.qr_image else ''
                if vendor.qr_image:
                    vendor.qr_image.delete(save=False)
                    vendor.qr_image = None
                    vendor.save(using='default')
                UserEditLog.objects.using('default').create(
                    target_user_id=vendor.id,
                    target_username=f"vendor:{vendor.code}",
                    edited_by=request.user.username,
                    changes=(
                        f"[QR] action=remove; old={old_name or '-'}; new=-; ip={ip_address}"
                    ),
                )
                messages.success(request, 'QR image removed.')
            elif 'qr_image' in request.FILES:
                old_name = vendor.qr_image.name if vendor.qr_image else ''
                action = 'replace' if old_name else 'upload'
                vendor.qr_image = request.FILES['qr_image']
                vendor.save(using='default')
                new_name = vendor.qr_image.name if vendor.qr_image else ''
                UserEditLog.objects.using('default').create(
                    target_user_id=vendor.id,
                    target_username=f"vendor:{vendor.code}",
                    edited_by=request.user.username,
                    changes=(
                        f"[QR] action={action}; old={old_name or '-'}; "
                        f"new={new_name or '-'}; ip={ip_address}"
                    ),
                )
                messages.success(request, 'QR image updated.')
            else:
                messages.error(request, 'No image file provided.')
        else:
            user_profile.phone = request.POST.get('phone', '').strip()
            user_profile.address = request.POST.get('address', '').strip()
            user_profile.city = request.POST.get('city', '').strip()
            user_profile.save()
            messages.success(request, 'Profile updated successfully.')
        return redirect('profile')

    return render(request, 'accounts/profile.html', {
        'profile': user_profile,
        'vendor': vendor,
        'qr_audit_logs': qr_audit_logs,
    })


@login_required
def change_password(request):
    """Allow any authenticated vendor user to change their own password."""
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


# ──────────────────────────────────────────────────────────────────────────────
# User management (vendor admin only)
# ──────────────────────────────────────────────────────────────────────────────

def _require_admin(request):
    """Returns the user's profile if they are tenant_admin or manager, else None."""
    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db:
        return None
    profile = UserProfile.objects.using(tenant_db).filter(user=request.user).first()
    if profile and profile.role in ('tenant_admin', 'manager'):
        return profile
    return None


@login_required
def manage_users(request):
    """List all staff users for this vendor."""
    tenant_db = getattr(request, 'tenant_db', None)
    admin_profile = _require_admin(request)
    if not admin_profile:
        messages.error(request, 'Only shop admins and managers can manage users.')
        return redirect('dashboard')

    users = (
        UserProfile.objects.using(tenant_db)
        .select_related('user')
        .exclude(role='superadmin')
        .order_by('role', 'user__username')
    )
    return render(request, 'accounts/manage_users.html', {
        'staff_users': users,
        'admin_profile': admin_profile,
    })


@login_required
def create_user(request):
    """Create a new staff user for this vendor."""
    tenant_db = getattr(request, 'tenant_db', None)
    admin_profile = _require_admin(request)
    if not admin_profile:
        messages.error(request, 'Only shop admins and managers can create users.')
        return redirect('dashboard')

    if request.method == 'POST':
        username      = request.POST.get('username', '').strip()
        email         = request.POST.get('email', '').strip()
        password      = request.POST.get('password', '').strip()
        password2     = request.POST.get('password2', '').strip()
        role          = request.POST.get('role', 'cashier')

        acc_inventory = request.POST.get('can_access_inventory') == 'on'
        acc_sales     = request.POST.get('can_access_sales') == 'on'
        acc_customers = request.POST.get('can_access_customers') == 'on'
        acc_reports   = request.POST.get('can_access_reports') == 'on'

        # Restrict role choices that non-admin managers can create
        allowed_roles = ['tenant_admin', 'manager', 'cashier', 'staff']
        if admin_profile.role == 'manager':
            allowed_roles = ['cashier', 'staff']

        errors = []
        if not username:
            errors.append('Username is required.')
        if not password:
            errors.append('Password is required.')
        if password != password2:
            errors.append('Passwords do not match.')
        if role not in allowed_roles:
            errors.append('Invalid role selection.')

        UserModel = get_user_model()
        existing_user = None
        if not errors:
            existing_user = UserModel.objects.using(tenant_db).filter(username__iexact=username).first()
            if existing_user:
                # Only block if a profile already exists for this user
                if UserProfile.objects.using(tenant_db).filter(user=existing_user).exists():
                    errors.append('A user with that username already exists.')

        if not errors:
            try:
                validate_password(password)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(request, 'accounts/create_user.html', {
                'admin_profile': admin_profile,
                'form_data': request.POST,
            })

        from apps.tenants.utils import set_current_tenant, ensure_tenant_schema
        tenant = getattr(request, 'tenant', None)
        if tenant:
            set_current_tenant(tenant, tenant_db)
        try:
            # Reuse orphaned user (no profile) or create a fresh one
            if existing_user:
                user = existing_user
                user.set_password(password)
                user.email = email
                user.save(using=tenant_db)
            else:
                user = UserModel._default_manager.db_manager(tenant_db).create_user(
                    username=username,
                    email=email,
                    password=password,
                )
            UserProfile.objects.using(tenant_db).create(
                user=user,
                tenant_id=getattr(getattr(request, 'tenant', None), 'id', None),
                role=role,
                can_access_inventory=acc_inventory,
                can_access_sales=acc_sales,
                can_access_customers=acc_customers,
                can_access_reports=acc_reports,
            )
        finally:
            set_current_tenant(None, None)

        logger.info("Admin '%s' created user '%s' in tenant '%s'.",
                    request.user.username, username,
                    getattr(getattr(request, 'tenant', None), 'code', '?'))
        messages.success(request, f"User '{username}' created successfully.")
        return redirect('manage_users')

    admin_profile = _require_admin(request)
    return render(request, 'accounts/create_user.html', {'admin_profile': admin_profile})


@login_required
def edit_user(request, user_id):
    """Edit a staff user's role, module access, and active status."""
    tenant_db = getattr(request, 'tenant_db', None)
    admin_profile = _require_admin(request)
    if not admin_profile:
        messages.error(request, 'Only shop admins and managers can edit users.')
        return redirect('dashboard')

    UserModel = get_user_model()
    target_user = get_object_or_404(UserModel.objects.using(tenant_db), pk=user_id)
    target_profile = UserProfile.objects.using(tenant_db).filter(user=target_user).first()

    # Prevent editing superadmin or own account via this view
    if not target_profile or target_profile.role == 'superadmin':
        messages.error(request, 'Cannot edit this user.')
        return redirect('manage_users')
    if target_user == request.user:
        messages.error(request, 'Use the Profile page to edit your own account.')
        return redirect('manage_users')
    # managers can't edit other managers or admins
    if admin_profile.role == 'manager' and target_profile.role in ('tenant_admin', 'manager'):
        messages.error(request, 'You do not have permission to edit this user.')
        return redirect('manage_users')

    if request.method == 'POST':
        role = request.POST.get('role', target_profile.role)
        allowed_roles = ['tenant_admin', 'manager', 'cashier', 'staff']
        if admin_profile.role == 'manager':
            allowed_roles = ['cashier', 'staff']
        if role not in allowed_roles:
            role = target_profile.role

        target_profile.role                = role
        target_profile.can_access_inventory = request.POST.get('can_access_inventory') == 'on'
        target_profile.can_access_sales     = request.POST.get('can_access_sales') == 'on'
        target_profile.can_access_customers = request.POST.get('can_access_customers') == 'on'
        target_profile.can_access_reports   = request.POST.get('can_access_reports') == 'on'
        target_profile.is_active            = request.POST.get('is_active') == 'on'
        target_profile.save(using=tenant_db)

        logger.info("Admin '%s' updated user '%s' in tenant '%s'.",
                    request.user.username, target_user.username,
                    getattr(getattr(request, 'tenant', None), 'code', '?'))
        messages.success(request, f"User '{target_user.username}' updated.")
        return redirect('manage_users')

    return render(request, 'accounts/edit_user.html', {
        'target_user': target_user,
        'target_profile': target_profile,
        'admin_profile': admin_profile,
    })
