# API Reference & Code Implementation Guide

## Superadmin Views API

### Dashboard View
```python
# URL: /tenants/superadmin/dashboard/
# Method: GET
# Required: @login_required, @superadmin_required

def superadmin_dashboard(request):
    """
    Returns: HTML page with vendor overview
    
    Context:
    {
        'vendors': QuerySet[Tenant],
        'total_vendors': int,
        'active_vendors': int,
        'inactive_vendors': int,
    }
    """
```

### Create Vendor
```python
# URL: /tenants/superadmin/create-vendor/
# Methods: GET (form), POST (create)
# Required: @login_required, @superadmin_required

def create_vendor(request):
    """
    GET: Returns create_vendor.html form
    
    POST Parameters:
    {
        'vendor_name': str,           # Required
        'vendor_code': str,           # Required, unique, lowercase+hyphens
        'owner_email': str,           # Required, unique
        'admin_password': str,        # Required, min 6 chars
        'admin_password2': str,       # Required, must match
    }
    
    Response:
    - Success: Redirects to superadmin_dashboard with success message
    - Error: Re-renders form with error message
    
    Side Effects:
    - Creates User in main DB
    - Creates UserProfile in main DB (role='admin')
    - Creates Tenant in main DB
    - Provisions new SQLite database
    - Runs migrations in new database
    - Creates User + UserProfile in vendor DB
    """
```

### Vendor Details
```python
# URL: /tenants/superadmin/vendor/<int:tenant_id>/
# Methods: GET (view), POST (update)
# Required: @login_required, @superadmin_required

def vendor_detail(request, tenant_id):
    """
    GET: Returns vendor_detail.html with vendor info
    
    POST Parameters:
    {
        'name': str,                  # Vendor name
        'status': str,                # active|inactive|suspended
        'access_customers': 'on'|'',  # Feature flag
        'access_inventory': 'on'|'',  # Feature flag
        'access_sales': 'on'|'',      # Feature flag
        'access_reports': 'on'|'',    # Feature flag
    }
    
    Response:
    - Success: Redirects with success message
    - Error: 404 if vendor not found
    
    Context:
    {
        'vendor': Tenant,
        'admin_user': User,
    }
    """
```

### Reset Vendor Password
```python
# URL: /tenants/superadmin/vendor/<int:tenant_id>/reset-password/
# Methods: GET (form), POST (update)
# Required: @login_required, @superadmin_required

def reset_vendor_password(request, tenant_id):
    """
    GET: Returns reset_vendor_password.html form
    
    POST Parameters:
    {
        'new_password': str,          # Required, min 6 chars
        'new_password2': str,         # Required, must match
    }
    
    Response:
    - Success: Updates password in both DBs, redirects
    - Error: Shows error message
    
    Side Effects:
    - Updates password in User (main DB)
    - Updates password in User (vendor DB)
    """
```

### Deactivate Vendor
```python
# URL: /tenants/superadmin/vendor/<int:tenant_id>/deactivate/
# Methods: GET (confirm), POST (deactivate)
# Required: @login_required, @superadmin_required

def deactivate_vendor(request, tenant_id):
    """
    GET: Returns deactivate_vendor.html confirmation page
    
    POST: Deactivates vendor
    
    Side Effects:
    - Sets tenant.is_active = False
    - Sets tenant.status = 'inactive'
    - Vendor cannot login after this
    """
```

### Superadmin Login As Vendor
```python
# URL: /tenants/superadmin/vendor/<int:tenant_id>/login-as/
# Method: GET
# Required: @login_required, superadmin check

def superadmin_login_as_vendor(request, tenant_id):
    """
    Allows superadmin to view vendor's shop
    
    Side Effects:
    - Sets session['tenant_id'] = tenant_id
    - Sets session['tenant_alias'] = db_alias
    - Sets session['superadmin_id'] = current_user.id (tracking)
    - Redirects to /accounts/ (vendor dashboard)
    
    Warning:
    - In production, consider making this read-only
    - Add audit logging for security
    """
```

## Authentication Views API

### Login View
```python
# URL: /accounts/login/
# Methods: GET (form), POST (authenticate)

def login_view(request):
    """
    Dual authentication system:
    
    1. Superadmin Login:
       - identifier: email or username
       - password: superadmin password
       - Redirects to /tenants/superadmin/dashboard/
    
    2. Vendor Admin Login:
       - identifier: vendor code
       - password: vendor admin password
       - Redirects to /accounts/ (vendor dashboard)
    
    POST Parameters:
    {
        'identifier': str,  # email/username or vendor code
        'password': str,    # password
    }
    
    Authentication Order:
    1. Try main DB (superadmin check)
    2. If not superadmin, try vendor DB
    3. If both fail, show error
    
    Session on Success:
    - Superadmin: session.pop('tenant_id') etc cleared
    - Vendor: session['tenant_id'] + session['tenant_alias'] set
    """
```

### Logout View
```python
# URL: /accounts/logout/
# Method: GET

def logout_view(request):
    """
    Clears session and redirects to login
    
    Side Effects:
    - Logs out user
    - Removes session['tenant_id']
    - Removes session['tenant_alias']
    """
```

## Management Commands API

### Create Superadmin
```bash
# Command: python manage.py create_superadmin

# Interactive mode:
$ python manage.py create_superadmin
Enter superadmin email: admin@example.com
Enter superadmin password: mypassword123

# Non-interactive mode:
$ python manage.py create_superadmin \
    --email=admin@example.com \
    --password=mypassword123

# Creates:
# - User with is_superuser=True
# - UserProfile with role='superadmin'
```

## Utility Functions (tenants.utils)

### Set Current Tenant
```python
from tenants.utils import set_current_tenant

# Usage:
set_current_tenant(tenant, db_alias)

# Args:
#   tenant: Tenant instance (or None to clear)
#   db_alias: str, Django DB alias (or None to clear)

# Effect:
#   Stores in thread-local storage for request duration
```

### Get Current Tenant
```python
from tenants.utils import get_current_tenant

# Usage:
tenant = get_current_tenant()

# Returns: Tenant instance or None
```

### Get Current Tenant DB
```python
from tenants.utils import get_current_tenant_db

# Usage:
db_alias = get_current_tenant_db()

# Returns: str (Django DB alias) or None
```

### Ensure Tenant Schema
```python
from tenants.utils import ensure_tenant_schema

# Usage:
db_alias = ensure_tenant_schema(tenant)

# Args:
#   tenant: Tenant instance
#
# Returns: str (Django DB alias like 'tenant_5')
#
# Creates if not exists:
# - Django database alias in settings.DATABASES
# - Database connection in connections.databases
# - Runs all pending migrations
```

### Ensure Tenant DB
```python
from tenants.utils import ensure_tenant_db

# Usage:
db_alias = ensure_tenant_db(tenant)

# Similar to ensure_tenant_schema but doesn't run migrations
```

### Provision Tenant Database
```python
from tenants.utils import provision_tenant_database

# Usage:
provision_tenant_database(tenant)

# Creates empty SQLite file:
# tenant_dbs/shop_{tenant_code}.sqlite3
```

### Migrate Tenant Database
```python
from tenants.utils import migrate_tenant_database

# Usage:
migrate_tenant_database(tenant)

# Runs all migrations on vendor database
# Equivalent to: python manage.py migrate --database=tenant_<id>
```

## Middleware API

### TenantMiddleware
```python
# Location: tenants/middleware.py

class TenantMiddleware:
    def __call__(self, request):
        """
        On every request:
        1. Check session['tenant_id']
        2. If exists, fetch Tenant from main DB
        3. Call ensure_tenant_db() to get db_alias
        4. Call set_current_tenant(tenant, db_alias)
        5. Attach to request as request.tenant, request.tenant_db
        6. Process view
        7. Call set_current_tenant(None, None) to clear
        """
```

### TenantAccessMiddleware
```python
# Location: tenants/middleware.py

class TenantAccessMiddleware:
    # Configuration:
    SECTION_RULES = (
        ('/customers/', 'access_customers'),
        ('/vendors/', 'access_vendors'),
        ('/inventory/', 'access_inventory'),
        ('/sales/', 'access_sales'),
        ('/reports/', 'access_reports'),
    )
    
    def __call__(self, request):
        """
        For each request URL:
        1. Check if it matches any section rule
        2. Get tenant from request
        3. Check if tenant has access to that section
        4. If not, return 403 Forbidden
        5. Otherwise, process normally
        """
```

## Database Router API

### TenantRouter
```python
# Location: tenants/db_router.py

class TenantRouter:
    def db_for_read(self, model, **hints):
        """
        Returns: Django DB alias
        
        Logic:
        - If get_current_tenant() is None → 'default'
        - If get_current_tenant() is set → tenant's db_alias
        """
    
    def db_for_write(self, model, **hints):
        """Same as db_for_read"""
    
    def allow_relation(self, obj1, obj2, **hints):
        """
        Allows relations only within same tenant
        """
    
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Permits migrations on correct database
        """
```

## Decorator API

### @superadmin_required
```python
# Location: tenants/views.py

@superadmin_required
def some_view(request):
    """
    Checks if user.profile.role == 'superadmin'
    
    If not:
    - Shows error message
    - Redirects to login
    
    If yes:
    - Proceeds with view
    """
```

## Model API

### Tenant Model
```python
from tenants.models import Tenant

# Fields:
tenant = Tenant.objects.get(code='abc-shop')
tenant.id                    # int, primary key
tenant.name                  # str, vendor display name
tenant.code                  # slug, unique identifier
tenant.owner_email           # str, admin email
tenant.db_name               # str, database filename
tenant.db_user               # str, optional DB user
tenant.db_password           # str, optional DB password
tenant.db_host               # str, default '127.0.0.1'
tenant.db_port               # str, default '5432'
tenant.access_customers      # bool, feature flag
tenant.access_inventory      # bool, feature flag
tenant.access_sales          # bool, feature flag
tenant.access_reports        # bool, feature flag
tenant.access_vendors        # bool, feature flag
tenant.status                # str, 'active'|'inactive'|'suspended'
tenant.admin_user            # FK to User, admin for this vendor
tenant.is_active             # bool, soft delete flag
tenant.created_at            # datetime, creation timestamp
tenant.updated_at            # datetime, last update timestamp

# Methods:
str(tenant)  # "ABC Shop (abc-shop)"
```

### UserProfile Model
```python
from accounts.models import UserProfile

# Fields:
profile = UserProfile.objects.get(user=request.user)
profile.id                   # int, primary key
profile.user                 # FK to User, one-to-one
profile.role                 # str, 'superadmin'|'admin'|'staff'|'manager'
profile.phone                # str, phone number
profile.address              # str, address
profile.city                 # str, city
profile.is_active            # bool
profile.created_date         # datetime

# Methods:
str(profile)  # "user@example.com (admin)"
```

## Common Code Patterns

### Get Vendor Admin User
```python
tenant = Tenant.objects.get(code='abc-shop')
admin_user = tenant.admin_user  # Returns User instance
```

### Check if User is Superadmin
```python
from accounts.models import UserProfile

try:
    is_superadmin = request.user.profile.role == 'superadmin'
except UserProfile.DoesNotExist:
    is_superadmin = False
```

### Query Vendor Data
```python
from inventory.models import Product
from tenants.utils import set_current_tenant, ensure_tenant_schema

tenant = Tenant.objects.using('default').get(code='abc-shop')
db_alias = ensure_tenant_schema(tenant)
set_current_tenant(tenant, db_alias)

# Now queries use tenant database
products = Product.objects.all()  # From vendor DB
```

### Create User in Vendor DB
```python
from django.contrib.auth.models import User
from accounts.models import UserProfile
from tenants.utils import ensure_tenant_schema, set_current_tenant

tenant = Tenant.objects.get(code='abc-shop')
db_alias = ensure_tenant_schema(tenant)
set_current_tenant(tenant, db_alias)

# Use db_alias for database selection
user = User.objects.db_manager(db_alias).create_user(
    username='staff@abc-shop.com',
    email='staff@abc-shop.com',
    password='password123'
)

UserProfile.objects.using(db_alias).create(
    user=user,
    role='staff'
)
```

### Check Module Access
```python
tenant = getattr(request, 'tenant', None)
if tenant and not tenant.access_inventory:
    # Inventory module is disabled for this vendor
    pass
```

---

This API reference provides complete documentation for extending and customizing the multi-tenant system.
