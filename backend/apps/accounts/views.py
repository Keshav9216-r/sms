import logging

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from .models import UserProfile
from apps.tenants.models import Tenant
from apps.tenants.utils import set_current_tenant, ensure_tenant_schema

logger = logging.getLogger('security')


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
                    request.session.cycle_key()  # Prevent session fixation
                    request.session.pop('tenant_id', None)
                    request.session.pop('tenant_alias', None)
                    logger.info("Superadmin '%s' logged in.", identifier)
                    return redirect('superadmin_dashboard')
                messages.error(request, 'Please use the superadmin login page.')
                return render(request, template_name)

        if original_tenant and original_db_alias:
            set_current_tenant(original_tenant, original_db_alias)

        # Try authenticate as vendor admin using shop code
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
                    request.session.cycle_key()  # Prevent session fixation
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
                    request.session.cycle_key()  # Prevent session fixation
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
                    logger.info("Vendor admin '%s' logged into tenant '%s'.", identifier, tenant.code)
                    return redirect('dashboard')

                # REMOVED: auto-creation of superuser accounts on login.
                # If the tenant admin user doesn't exist in the tenant DB, the
                # vendor setup is incomplete. Log the anomaly and reject login.
                if not user and tenant.admin_user.check_password(password):
                    logger.warning(
                        "Vendor admin user missing in tenant DB for tenant '%s' (email=%s). "
                        "Tenant DB provisioning may be incomplete.",
                        tenant.code, lookup_email,
                    )
                    messages.error(
                        request,
                        'Account setup is incomplete. Please contact the administrator.',
                    )
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


def user_login_view(request):
    return _handle_login(request, 'accounts/user_login.html', allow_superadmin=False)


def superadmin_login_view(request):
    return _handle_login(request, 'accounts/superadmin_login.html', allow_superadmin=True)


def logout_view(request):
    logger.info("User '%s' logged out.", request.user.username if request.user.is_authenticated else 'anonymous')
    logout(request)
    request.session.pop('tenant_id', None)
    request.session.pop('tenant_alias', None)
    return redirect('login')


@login_required
def dashboard(request):
    """Dashboard for vendor admins"""
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

    # Fetch vendor/shop details from the main DB using tenant_id in session
    vendor = None
    tenant_id = request.session.get('tenant_id')
    if tenant_id:
        vendor = Tenant.objects.using('default').filter(id=tenant_id).first()
    if vendor is None:
        vendor = getattr(request, 'tenant', None)

    if request.method == 'POST':
        user_profile.phone = request.POST.get('phone', '').strip()
        user_profile.address = request.POST.get('address', '').strip()
        user_profile.city = request.POST.get('city', '').strip()
        user_profile.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')
    return render(request, 'accounts/profile.html', {
        'profile': user_profile,
        'vendor': vendor,
    })


@login_required
def change_password(request):
    """Allow any authenticated vendor user to change their own password."""
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '').strip()
        new_password = request.POST.get('new_password', '').strip()
        new_password2 = request.POST.get('new_password2', '').strip()

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
