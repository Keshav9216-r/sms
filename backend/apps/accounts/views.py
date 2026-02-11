from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import UserProfile
from apps.tenants.models import Tenant
from apps.tenants.utils import set_current_tenant, ensure_tenant_schema

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
                    request.session.pop('tenant_id', None)
                    request.session.pop('tenant_alias', None)
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
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
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
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
                    return redirect('dashboard')

                if not user and tenant.admin_user.check_password(password):
                    tenant_admin = UserModel._default_manager.db_manager(db_alias).create_user(
                        username=lookup_email,
                        email=lookup_email,
                        password=password,
                        is_staff=True,
                        is_superuser=True,
                    )
                    UserProfile.objects.using(db_alias).get_or_create(
                        user=tenant_admin,
                        defaults={'role': 'tenant_admin', 'tenant_id': tenant.id},
                    )
                    set_current_tenant(None, None)
                    tenant_admin.backend = 'apps.tenants.auth_backends.TenantModelBackend'
                    login(request, tenant_admin)
                    request.session['tenant_id'] = tenant.id
                    request.session['tenant_alias'] = db_alias
                    return redirect('dashboard')
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
    logout(request)
    request.session.pop('tenant_id', None)
    request.session.pop('tenant_alias', None)
    return redirect('login')

@login_required
def dashboard(request):
    """Dashboard for vendor admins"""
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        user_profile = UserProfile.objects.create(
            user=request.user,
            role='cashier',
            tenant=getattr(request, 'tenant', None),
        )
    
    # Get summary data for dashboard
    from apps.inventory.models import Product, Inventory
    from apps.sales.models import Sale
    from apps.customers.models import Customer
    from django.utils import timezone
    from django.db.models import F
    
    context = {
        'user_profile': user_profile,
        'total_products': Product.objects.count(),
        'low_stock_items': Inventory.objects.filter(quantity_in_stock__lte=F('product__reorder_level')).count(),
        'total_customers': Customer.objects.count(),
        'today_sales': Sale.objects.filter(sale_date__date=timezone.now().date()).count(),
    }
    return render(request, 'reports/dashboard.html', context)

@login_required
def profile(request):
    """User profile management"""
    try:
        profile_obj = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        profile_obj = UserProfile.objects.create(
            user=request.user,
            role='cashier',
            tenant=getattr(request, 'tenant', None),
        )
    
    if request.method == 'POST':
        profile_obj.phone = request.POST.get('phone')
        profile_obj.address = request.POST.get('address')
        profile_obj.city = request.POST.get('city')
        profile_obj.save()
        return redirect('dashboard')
    return render(request, 'accounts/profile.html', {'profile': profile_obj})

