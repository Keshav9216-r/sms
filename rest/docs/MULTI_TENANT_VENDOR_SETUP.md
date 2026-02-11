# Multi-Tenant Vendor System Implementation

## Overview
This system implements a multi-tenant architecture where:
- **Superadmins** manage all vendors (shops) from a central dashboard
- **Vendor Admins** manage their own shop's data in isolated databases
- **Vendors cannot self-register** - they are created by superadmin only
- Each vendor has **complete data isolation** with their own SQLite database

## Architecture Changes

### 1. User Roles (Updated)
Located in [accounts/models.py](../accounts/models.py):

```
- superadmin     : Manages all vendors, creates vendor accounts
- admin          : Vendor admin - manages single vendor's data
- staff          : Shop staff - operational users
- manager        : Manager role
```

### 2. Tenant Model (Updated)
Located in [tenants/models.py](../tenants/models.py):

- Renamed to represent **Vendors** (shops)
- Added `status` field: active, inactive, suspended
- Added `admin_user` ForeignKey to User model
- Tracks which User is the admin for this vendor
- Feature access control per vendor

### 3. Database Structure

**Main Database (default):**
- Stores: Superadmins, Tenant/Vendor definitions, Django admin data
- Users: Only superadmins created here

**Vendor Databases:**
- Each vendor has isolated SQLite database: `shop_{vendor_code}.sqlite3`
- Located in `/workspaces/top/tenant_dbs/` directory
- Contains: Vendor-specific users, products, sales, customers, etc.
- Only the vendor admin + staff can access this database

## Workflow

### Creating a Vendor (Superadmin Only)

1. **Superadmin logs in** with email/username
   - Login at: `/accounts/login/`
   - Redirects to: `/tenants/superadmin/dashboard/`

2. **Create New Vendor**
   - Go to: `/tenants/superadmin/create-vendor/`
   - Fill: Vendor name, code, admin email, password
   - System creates:
     - Admin user in **main database**
     - Tenant record linking to admin user
     - New vendor database with schema
     - Admin user in **vendor database**

3. **Vendor Admin logs in**
   - Go to: `/accounts/login/`
   - Enter: vendor code + admin password
   - Access: `/accounts/` (vendor dashboard)
   - Can only see their own data

### Superadmin Functions

**Dashboard**: `/tenants/superadmin/dashboard/`
- View all vendors
- See vendor stats
- Quick actions

**Vendor Management**: `/tenants/superadmin/vendor/<id>/`
- Edit vendor details
- Control feature access
- Reset vendor admin password
- Deactivate vendor

**Login as Vendor**: `/tenants/superadmin/vendor/<id>/login-as/`
- Superadmin can view vendor's shop as if logged in
- Useful for troubleshooting
- Session tracks superadmin ID

## File Changes

### Models Updated
- [accounts/models.py](../accounts/models.py) - Added superadmin role
- [tenants/models.py](../tenants/models.py) - Added status, admin_user FK

### Views Created/Updated
- [accounts/views.py](../accounts/views.py) - Updated login for dual auth (superadmin + vendor)
- [tenants/views.py](../tenants/views.py) - **NEW** - Superadmin management views

### URLs Updated
- [accounts/urls.py](../accounts/urls.py) - Removed register endpoint
- [tenants/urls.py](../tenants/urls.py) - **NEW** - Superadmin paths

### Templates Created
- [templates/tenants/superadmin_dashboard.html](../templates/tenants/superadmin_dashboard.html)
- [templates/tenants/create_vendor.html](../templates/tenants/create_vendor.html)
- [templates/tenants/vendor_detail.html](../templates/tenants/vendor_detail.html)
- [templates/tenants/reset_vendor_password.html](../templates/tenants/reset_vendor_password.html)
- [templates/tenants/deactivate_vendor.html](../templates/tenants/deactivate_vendor.html)

### Management Commands Created
- [accounts/management/commands/create_superadmin.py](../accounts/management/commands/create_superadmin.py)

### Migrations Created
- [accounts/migrations/0002_alter_userprofile_role.py](../accounts/migrations/0002_alter_userprofile_role.py)
- [tenants/migrations/0004_add_status_and_admin_user.py](../tenants/migrations/0004_add_status_and_admin_user.py)

## Installation & Setup

### 1. Apply Migrations
```bash
python manage.py migrate
```

### 2. Create Superadmin User
```bash
# Option A: Interactive
python manage.py create_superadmin

# Option B: Non-interactive
python manage.py create_superadmin --email=superadmin@example.com --password=<set-strong-password>
```

### 3. Login
- Go to: `http://localhost:8000/accounts/login/`
- Use superadmin email + password
- You'll be redirected to: `/tenants/superadmin/dashboard/`

### 4. Create First Vendor
- Click "Create Vendor"
- Fill vendor details
- Vendor admin can now login using vendor code

## Security Features

1. **Role-based Access Control**
   - Superadmin decorator on all superadmin views
   - Only superadmin can create/manage vendors

2. **Database Isolation**
   - Each vendor's data in separate database
   - Users from one vendor cannot access another's database
   - Middleware enforces tenant context

3. **Login Authentication**
   - Superadmins: Standard Django auth on main DB
   - Vendor Admins: Tenant-aware auth on vendor DB
   - Shop code + password required for vendor login

4. **Feature Control**
   - Superadmin can enable/disable modules per vendor
   - Middleware enforces module access (TenantAccessMiddleware)

## Key Functions

### Superadmin Creation
```python
from django.contrib.auth.models import User
from accounts.models import UserProfile

superadmin = User.objects.create_superuser(
    username='admin@example.com',
    email='admin@example.com',
    password='secure_password'
)
UserProfile.objects.create(user=superadmin, role='superadmin')
```

### Creating Vendor (In Views)
```python
# 1. Create admin user in main DB
admin_user = User.objects.create_user(
    username=email,
    email=email,
    password=password,
    is_staff=True
)
UserProfile.objects.create(user=admin_user, role='admin')

# 2. Create tenant record
tenant = Tenant.objects.create(
    name=vendor_name,
    code=vendor_code,
    owner_email=email,
    db_name=f'shop_{vendor_code}',
    admin_user=admin_user
)

# 3. Provision and migrate database
provision_tenant_database(tenant)
migrate_tenant_database(tenant)

# 4. Create admin in vendor database
db_alias = ensure_tenant_schema(tenant)
set_current_tenant(tenant, db_alias)
# Create user using db_alias...
```

## Data Flow Diagrams

### Login Flow
```
User visits /accounts/login/
    ↓
Enter credentials
    ↓
Check if superadmin (main DB) → YES → Redirect to /tenants/superadmin/dashboard/
    ↓ NO
Check if vendor code exists → YES → Authenticate in vendor DB → Redirect to /accounts/
    ↓ NO
Show login error
```

### Vendor Creation Flow
```
Superadmin → /tenants/superadmin/create-vendor/
    ↓
Fill vendor form
    ↓
Create admin user in main DB → UserProfile(role='admin')
    ↓
Create Tenant record with admin_user FK
    ↓
Provision vendor database
    ↓
Migrate vendor database
    ↓
Create admin user in vendor database → UserProfile(role='admin')
    ↓
Success! Vendor can now login
```

## Access URLs

### Superadmin Access
- Dashboard: `/tenants/superadmin/dashboard/`
- Create Vendor: `/tenants/superadmin/create-vendor/`
- Vendor Details: `/tenants/superadmin/vendor/<id>/`
- Reset Password: `/tenants/superadmin/vendor/<id>/reset-password/`
- Deactivate Vendor: `/tenants/superadmin/vendor/<id>/deactivate/`
- Login As: `/tenants/superadmin/vendor/<id>/login-as/`

### Vendor Admin Access
- Login: `/accounts/login/`
- Dashboard: `/accounts/`
- Profile: `/accounts/profile/`
- All shop features: `/inventory/`, `/sales/`, `/customers/`, etc.

## Notes

1. **Vendor Signup Removed**: No public registration for vendors
2. **Isolated Data**: Each vendor only sees their data
3. **Superadmin Visibility**: Can view all vendors and temporarily login as vendor
4. **Password Management**: Superadmin can reset vendor admin passwords
5. **Feature Control**: Can disable modules per vendor
6. **Scalability**: Each new vendor gets own database, scales independently

## Troubleshooting

### Issue: Vendor cannot login
- Check if vendor `is_active=True`
- Verify vendor code is correct (case-insensitive)
- Confirm admin user exists in both DBs

### Issue: Data not appearing in vendor DB
- Ensure migrations were run: `python manage.py migrate --database=tenant_<id>`
- Check `request.session['tenant_alias']` is set correctly

### Issue: Superadmin cannot create vendor
- Verify superadmin has `role='superadmin'` in UserProfile
- Check if email already exists in User table

## Future Enhancements

1. Add vendor subscription tiers
2. Usage analytics per vendor
3. Automated backups per vendor
4. Vendor API keys for external integrations
5. Vendor usage reports (storage, transactions)
6. Bulk vendor operations
7. Vendor invitation system
8. Multi-admin per vendor support
