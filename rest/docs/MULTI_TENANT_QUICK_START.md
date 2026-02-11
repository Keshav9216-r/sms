# Quick Start: Multi-Tenant Vendor System

## Step 1: Apply Migrations
```bash
cd /workspaces/top
python manage.py migrate
```

## Step 2: Create Superadmin
```bash
python manage.py create_superadmin
# Interactive prompts for email and password
# Or use: python manage.py create_superadmin --email=admin@example.com --password=<set-strong-password>
```

## Step 3: Start Server
```bash
python manage.py runserver
```

## Step 4: Login as Superadmin
- URL: `http://localhost:8000/accounts/login/`
- Use superadmin email and password
- You'll be redirected to superadmin dashboard

## Step 5: Create Your First Vendor
- Click "Create Vendor" button
- Fill in:
  - **Vendor Name**: e.g., "ABC Shop"
  - **Vendor Code**: e.g., "abc-shop" (lowercase, hyphens allowed)
  - **Admin Email**: e.g., "admin@abc-shop.com"
  - **Admin Password**: Secure password for vendor admin
- Click "Create Vendor"

## Step 6: Login as Vendor Admin
- Logout from superadmin (or use different browser)
- URL: `http://localhost:8000/accounts/login/`
- Enter:
  - **Identifier**: `abc-shop` (the vendor code)
  - **Password**: Admin password created in step 5
- Click Login
- You'll see vendor's dashboard with their own data

## Management from Superadmin Panel
- View all vendors: `/tenants/superadmin/dashboard/`
- Edit vendor: Click "View" on any vendor
- Control features: Enable/disable modules per vendor
- Reset password: Click "Reset Admin Password"
- Temporarily view vendor: Click "Login as"
- Deactivate vendor: Click "Deactivate Vendor"

## Key Points

✓ Vendors do NOT have self-registration  
✓ Superadmin creates all vendor accounts  
✓ Each vendor has isolated database  
✓ Vendor data is completely separated  
✓ Superadmin can monitor all vendors  

## Database Files

Vendor databases are stored in: `/workspaces/top/tenant_dbs/`

Example structure:
```
tenant_dbs/
  ├── shop_abc-shop.sqlite3      (Vendor 1 database)
  ├── shop_xyz-store.sqlite3     (Vendor 2 database)
  └── ...
```

Each database has:
- Products and inventory (vendor-specific)
- Sales and transactions
- Customers
- Users (vendor admin + staff)
- All other shop data

## Common Tasks

### Add Staff Member to Vendor
1. Superadmin logs in as vendor using "Login as"
2. Go to Admin panel: `/admin/`
3. Create new user with staff role
4. User can now access that vendor's shop

### Disable a Module for Vendor
1. Go to vendor detail: `/tenants/superadmin/vendor/<id>/`
2. Uncheck the module (e.g., uncheck "Access Inventory")
3. Click "Update Vendor"
4. Vendor loses access to that module

### Reset Vendor Admin Password
1. Go to superadmin dashboard
2. Click "View" on vendor
3. Click "Reset Admin Password"
4. Enter new password
5. Vendor admin must use new password to login

### Deactivate a Vendor
1. Go to vendor detail
2. Click "Deactivate Vendor"
3. Confirm
4. Vendor is set to inactive and cannot login

## File Locations

- **Superadmin Views**: [tenants/views.py](../tenants/views.py)
- **Superadmin URLs**: [tenants/urls.py](../tenants/urls.py)
- **Superadmin Templates**: [templates/tenants/](../templates/tenants/)
- **Create Superadmin Command**: [accounts/management/commands/create_superadmin.py](../accounts/management/commands/create_superadmin.py)
- **Full Documentation**: [MULTI_TENANT_VENDOR_SETUP.md](./MULTI_TENANT_VENDOR_SETUP.md)

## Troubleshooting

**Q: Vendor can't login?**  
A: Check vendor code is correct and status is 'active'

**Q: Getting database error?**  
A: Run migrations with `python manage.py migrate`

**Q: Superadmin login not working?**  
A: Ensure user has `role='superadmin'` in UserProfile

**Q: Can't create superadmin?**  
A: Make sure migrations are applied first

## Next Steps

- Customize vendor dashboard in [templates/reports/dashboard.html](../templates/reports/dashboard.html)
- Add more staff members via Django admin
- Configure permission levels for different roles
- Set up daily backup scripts for each vendor DB
- Monitor vendor usage and analytics
