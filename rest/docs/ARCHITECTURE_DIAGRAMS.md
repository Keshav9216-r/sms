# System Architecture & Data Flow Diagrams

## 1. User Authentication Flow

```
                    User Access Point
                         │
                         ▼
              ┌────────────────────┐
              │  /accounts/login/  │
              └────────┬───────────┘
                       │
         Credentials: email + password OR code + password
         │
         ▼
    ┌─────────────────────────┐
    │ Is Superadmin?          │
    │ (Main DB check)         │
    │ role == 'superadmin'    │
    └──────┬──────────────────┘
           │
      YES  │  NO
           │   │
    ┌──────▼┐ │
    │ Auth  │ │
    │ Main  │ │
    │ DB    │ │
    └──┬───┘ │
       │     ▼
       │   ┌─────────────────────────┐
       │   │ Vendor Code exists?     │
       │   │ Check Tenant table      │
       │   └──────┬──────────────────┘
       │          │
       │      YES │  NO
       │          │   │
       │          ▼   ▼
       │       ┌────────────────┐
       │       │ Auth Tenant DB │ error
       │       │ (vendor DB)    │
       │       └────┬───────────┘
       │            │
       │            ▼
       │        ┌──────────────────────────┐
       │        │ Set session:             │
       │        │ - tenant_id              │
       │        │ - tenant_alias           │
       │        └──────┬───────────────────┘
       │               │
       └───────┬───────┘
               │
               ▼
      ┌────────────────────┐
      │ Redirect           │
      │ /tenants/superadmin│  Superadmin Dashboard
      │ /accounts/         │  Vendor Dashboard
      └────────────────────┘
```

## 2. Vendor Creation Process

```
                    Superadmin
                        │
                        ▼
          ┌──────────────────────────┐
          │  Create Vendor Form      │
          │ /tenants/superadmin/     │
          │ create-vendor/           │
          └───────────┬──────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ Validate Input             │
         │ - vendor_name              │
         │ - vendor_code (unique)     │
         │ - owner_email (unique)     │
         │ - admin_password           │
         └────────┬───────────────────┘
                  │
         ┌────────▼─────────┐
         │ Valid? ──────NO──┐ Error Message
         └────┬──────────┘
              │ YES
              ▼
    ┌─────────────────────────────────────┐
    │ Create Admin User (Main DB)         │
    │ - username = email                  │
    │ - is_staff = True                   │
    │ - password = hashed                 │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Create UserProfile (Main DB)        │
    │ - user = admin_user                 │
    │ - role = 'admin'                    │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Create Tenant Record (Main DB)      │
    │ - name = vendor_name                │
    │ - code = vendor_code                │
    │ - owner_email = email               │
    │ - db_name = shop_{code}             │
    │ - admin_user = FK to admin_user     │
    │ - status = 'active'                 │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Provision Vendor Database           │
    │ Create: tenant_dbs/shop_{code}.db  │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Migrate Vendor Database             │
    │ Run all migrations in vendor DB     │
    │ (products, sales, customers, etc)   │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Create Admin User (Vendor DB)       │
    │ - Same email/password as main DB    │
    │ - is_superuser = True in vendor DB  │
    │ - role = 'admin'                    │
    └──────────┬────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Vendor Ready!                       │
    │ Admin can now login with:           │
    │ - Code: {vendor_code}               │
    │ - Password: {admin_password}        │
    └─────────────────────────────────────┘
```

## 3. Data Isolation Architecture

```
┌──────────────────────────────────────────────────────────┐
│                 APPLICATION LAYER                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Superadmin Portal │ Vendor Admin Portal │ Staff  │   │
│  └─────────┬──────────────┬──────────────────┬──────┘   │
└───────────┼──────────────┼──────────────────┼──────────┘
            │              │                  │
            ▼              ▼                  ▼
┌──────────────────────────────────────────────────────────┐
│              MIDDLEWARE LAYER                            │
│  ┌──────────────────────────────────────────────────┐   │
│  │ TenantMiddleware                                 │   │
│  │ - Check session['tenant_id']                     │   │
│  │ - Set current_tenant context                     │   │
│  │ - Route DB queries to correct database           │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │ TenantAccessMiddleware                           │   │
│  │ - Check feature flags per vendor                 │   │
│  │ - Block unauthorized module access               │   │
│  └──────────────────────────────────────────────────┘   │
└───┬──────────────────┬──────────────────┬────────────────┘
    │                  │                  │
    ▼                  ▼                  ▼
┌───────────┐      ┌───────────┐     ┌───────────┐
│ Main DB   │      │ Tenant DB1│     │ Tenant DB2│
│ (SQLite)  │      │ (SQLite)  │     │ (SQLite)  │
├───────────┤      ├───────────┤     ├───────────┤
│ Users     │      │ Users     │     │ Users     │
│  (super)  │      │  (admin)  │     │  (admin)  │
├───────────┤      ├───────────┤     ├───────────┤
│ Tenant    │      │ Products  │     │ Products  │
│ Records   │      │ Sales     │     │ Sales     │
└───────────┘      │ Customers │     │ Customers │
   File:           │ Reports   │     │ Reports   │
   db.sqlite3      └───────────┘     └───────────┘
                   File:              File:
                   shop_vendor1.db   shop_vendor2.db
                   
    ┌──────────────────────────────────────┐
    │ Database Router (db_router.py)       │
    │ - Check get_current_tenant()         │
    │ - Route to main or tenant DB         │
    │ - Enforce read/write per tenant      │
    └──────────────────────────────────────┘
```

## 4. Vendor Admin Dashboard Flow

```
        Vendor Admin Logged In
                 │
                 ▼
    ┌────────────────────────────────┐
    │ /accounts/                     │
    │ Dashboard View                 │
    │ (Uses current tenant context)  │
    └────────────┬───────────────────┘
                 │
        Fetches from Vendor DB Only:
        │
        ├─ Product.objects.all()  ─┐
        │                           │ Using
        ├─ Sale.objects.all()  ──┬─ current
        │                        │  tenant
        ├─ Customer.objects.all()┤  database
        │                        │
        └─ Inventory.objects.all─┘
        │
        ▼
    ┌────────────────────────────────┐
    │ Display Vendor-Specific Data   │
    │ - Total Products              │
    │ - Low Stock Items             │
    │ - Total Customers             │
    │ - Today's Sales               │
    └────────────────────────────────┘
```

## 5. Superadmin "Login As Vendor" Flow

```
        Superadmin at Dashboard
                 │
                 ▼
    ┌──────────────────────────────────┐
    │ Click "Login as" for Vendor      │
    │ /tenants/superadmin/vendor/<id>/ │
    │ login-as/                        │
    └───────────────┬──────────────────┘
                    │
                    ▼
    ┌──────────────────────────────────┐
    │ Set Session Context:             │
    │ - session['tenant_id'] = id      │
    │ - session['tenant_alias'] = db   │
    │ - session['superadmin_id'] =     │
    │   current_user.id (tracking)     │
    └───────────────┬──────────────────┘
                    │
                    ▼
    ┌──────────────────────────────────┐
    │ Redirect to /accounts/           │
    │ (Dashboard loads vendor context) │
    │                                  │
    │ NOTE: Superadmin's user is NOT   │
    │ owner of this database, but      │
    │ session routes queries here      │
    └───────────────┬──────────────────┘
                    │
                    ▼
    ┌──────────────────────────────────┐
    │ View Vendor Dashboard            │
    │ See vendor's products, sales, etc│
    │ for troubleshooting/support      │
    │                                  │
    │ Cannot modify (read-only view    │
    │ recommended in production)       │
    └───────────────┬──────────────────┘
                    │
                    ▼
    ┌──────────────────────────────────┐
    │ Clear session:                   │
    │ - Click logout or close browser  │
    │ - session['tenant_id'] removed   │
    │ - Back to superadmin dashboard   │
    └──────────────────────────────────┘
```

## 6. Module Access Control Flow

```
        Vendor Admin Requests /inventory/
                    │
                    ▼
        ┌───────────────────────────┐
        │ TenantAccessMiddleware    │
        │ Checks prefix             │
        │ '/inventory/' found       │
        └──────────┬────────────────┘
                   │
                   ▼
        ┌───────────────────────────┐
        │ Get Tenant from Session   │
        │ tenant = Tenant.objects   │
        │ .get(id=session['tenant'])|
        └──────────┬────────────────┘
                   │
                   ▼
        ┌───────────────────────────┐
        │ Check Flag:               │
        │ tenant.access_inventory   │
        │ == True?                  │
        └──────┬──────────────────┐─┘
             YES│             NO │
               │                │
          ┌────▼────┐       ┌───▼────────────┐
          │ Allow    │       │ Return 403     │
          │ Access   │       │ Forbidden      │
          │ Inventory│       │ "Access denied"│
          │ Module   │       └────────────────┘
          └──────────┘
```

## 7. Database Query Routing

```
ORM Query Example:
Product.objects.all()
            │
            ▼
    ┌──────────────────────────┐
    │ Django ORM Layer         │
    │ (Intercepts query)       │
    └───────────┬──────────────┘
                │
                ▼
    ┌──────────────────────────────────────┐
    │ db_router.py                         │
    │ db_for_read() / db_for_write()       │
    │                                      │
    │ Check: get_current_tenant()          │
    │ - None? → Use 'default' (main DB)    │
    │ - Set? → Use tenant's db_alias      │
    └───────────┬──────────────────────────┘
                │
                ▼
    ┌──────────────────────────────────────┐
    │ Database Connection                  │
    │ settings.DATABASES[db_alias]         │
    │                                      │
    │ For Superadmin: default DB           │
    │ For Vendor: tenant_{id} DB           │
    └───────────┬──────────────────────────┘
                │
                ▼
    ┌──────────────────────────────────────┐
    │ SQLite File                          │
    │ - db.sqlite3 (main)                  │
    │ - tenant_dbs/shop_{code}.sqlite3     │
    └──────────────────────────────────────┘
```

## 8. Permission Matrix

```
                   │ Superadmin │ Vendor Admin │ Staff │ Customer │
─────────────────────────────────────────────────────────────────────
Create Vendor     │    ✓       │      ✗       │  ✗    │    ✗     │
Manage Vendors    │    ✓       │      ✗       │  ✗    │    ✗     │
View Own Data     │    ✓*      │      ✓       │  ✓    │    ✓     │
View Other Data   │    ✓       │      ✗       │  ✗    │    ✗     │
Create Products   │    ✗       │      ✓       │  ✓    │    ✗     │
Create Sales      │    ✗       │      ✓       │  ✓    │    ✗     │
Generate Reports  │    ✗       │      ✓**     │  ✓**  │    ✗     │
Access Admin      │    ✓       │      ✓       │  ✗    │    ✗     │
─────────────────────────────────────────────────────────────────────

Legend:
✓ = Allowed
✗ = Denied
* = Can switch to any vendor view
** = If feature enabled for vendor
```

## 9. Session Management

```
┌─────────────────────────────────────────────────────┐
│ Request with Session                                │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
    ┌────────────────────────────────────────┐
    │ Check session['tenant_id']             │
    │                                        │
    │ Exists? ┌─── YES ──┐                  │
    │         │          NO                 │
    │         ▼          │                  │
    │    Fetch    ┌──────▼────────────────┐
    │    Tenant   │ Use Main DB           │
    │    Record   │ (Superadmin context)  │
    │    from     └──────────────────────┘
    │    Main DB
    │         │
    │         ▼
    │    ┌──────────────────────┐
    │    │ Call ensure_         │
    │    │ tenant_schema()      │
    │    │                      │
    │    │ Creates db_alias:    │
    │    │ "tenant_{id}"        │
    │    └──────┬───────────────┘
    │           │
    │           ▼
    │    ┌──────────────────────┐
    │    │ Call set_            │
    │    │ current_tenant()     │
    │    │                      │
    │    │ Stores in thread     │
    │    │ local for request    │
    │    │ duration             │
    │    └──────────────────────┘
    │
    └────────────────────────────────────────┘
             │
             ▼
    ┌────────────────────────────────────────┐
    │ View receives request                  │
    │ - get_current_tenant() available       │
    │ - get_current_tenant_db() available    │
    │                                        │
    │ All ORM queries route to correct DB    │
    └────────────────────────────────────────┘
             │
             ▼
    ┌────────────────────────────────────────┐
    │ Response generated                     │
    │                                        │
    │ Middleware calls:                      │
    │ set_current_tenant(None, None)         │
    │                                        │
    │ Clears thread local for next request   │
    └────────────────────────────────────────┘
```

---

This architecture ensures:
- ✓ Complete data isolation between vendors
- ✓ Scalable multi-tenant support
- ✓ Centralized superadmin control
- ✓ Flexible feature management
- ✓ Clean separation of concerns
