# Multi-Tenant System: Visual Setup Guide

## System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                    Django Shop Management                       │
│                                                                 │
│  ┌──────────────────────┐  ┌────────────────────────────────┐ │
│  │   Main Application   │  │  Multi-Tenant Components       │ │
│  ├──────────────────────┤  ├────────────────────────────────┤ │
│  │ - accounts/          │  │ - tenants/views.py (NEW)      │ │
│  │ - inventory/         │  │ - tenants/urls.py (NEW)       │ │
│  │ - sales/             │  │ - tenants/middleware.py       │ │
│  │ - customers/         │  │ - tenants/db_router.py        │ │
│  │ - reports/           │  │ - Tenant model (updated)      │ │
│  │ - vendors/           │  │                               │ │
│  └──────────────────────┘  └────────────────────────────────┘ │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │              Authentication System                       │ │
│  ├──────────────────────────────────────────────────────────┤ │
│  │  Superadmin          │  Vendor Admin                    │ │
│  │  ├─ email/username   │  ├─ vendor code                 │ │
│  │  ├─ password         │  ├─ password                    │ │
│  │  ├─ Main DB auth     │  ├─ Tenant DB auth             │ │
│  │  └─ role='superadmin'│  └─ role='admin'               │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## File Organization

```
/workspaces/top/
│
├── 📄 Core Files (Django)
│   ├── manage.py
│   ├── db.sqlite3 (Main Database)
│   └── requirements.txt
│
├── 📁 shop_management/ (Settings)
│   ├── settings.py
│   ├── urls.py (✏️ UPDATED: added tenants/)
│   ├── wsgi.py
│   └── asgi.py
│
├── 📁 accounts/ (User Management)
│   ├── models.py (✏️ UPDATED: added superadmin role)
│   ├── views.py (✏️ UPDATED: dual auth login)
│   ├── urls.py (✏️ UPDATED: removed register)
│   ├── migrations/
│   │   ├── 0001_initial.py
│   │   └── 0002_alter_userprofile_role.py (✨ NEW)
│   ├── management/ (✨ NEW)
│   │   ├── __init__.py
│   │   └── commands/
│   │       ├── __init__.py
│   │       └── create_superadmin.py (✨ NEW)
│   └── templates/accounts/
│       ├── login.html
│       └── ...
│
├── 📁 tenants/ (Multi-Tenant Management)
│   ├── models.py (✏️ UPDATED: added status, admin_user)
│   ├── views.py (✨ NEW: 450+ lines, superadmin functions)
│   ├── urls.py (✨ NEW: superadmin routes)
│   ├── middleware.py (Existing: tenant context)
│   ├── db_router.py (Existing: database routing)
│   ├── auth_backends.py (Existing)
│   ├── migrations/
│   │   ├── 0001_initial.py
│   │   ├── 0002_add_owner_email_column.py
│   │   ├── 0003_add_access_flags_columns.py
│   │   └── 0004_add_status_and_admin_user.py (✨ NEW)
│   └── management/
│       └── commands/
│           └── (existing management commands)
│
├── 📁 inventory/, sales/, customers/, reports/, vendors/
│   └── (Existing modules, unchanged)
│
├── 📁 templates/
│   ├── base.html
│   ├── accounts/
│   ├── inventory/
│   ├── sales/
│   ├── customers/
│   ├── reports/
│   ├── vendors/
│   └── tenants/ (✨ NEW)
│       ├── superadmin_dashboard.html (✨ NEW)
│       ├── create_vendor.html (✨ NEW)
│       ├── vendor_detail.html (✨ NEW)
│       ├── reset_vendor_password.html (✨ NEW)
│       └── deactivate_vendor.html (✨ NEW)
│
├── 📁 tenant_dbs/ (Vendor Databases)
│   ├── shop_vendor-code-1.sqlite3 (✨ NEW when vendor created)
│   ├── shop_vendor-code-2.sqlite3 (✨ NEW when vendor created)
│   └── ... (one per vendor)
│
├── 📁 static/ (JavaScript, CSS)
├── 📁 media/ (Product images, etc)
│
└── 📁 Documentation/ (✨ NEW)
    ├── MULTI_TENANT_VENDOR_SETUP.md (✨ NEW: 400+ lines)
    ├── MULTI_TENANT_QUICK_START.md (✨ NEW: 200+ lines)
    ├── ARCHITECTURE_DIAGRAMS.md (✨ NEW: 400+ lines)
    ├── API_REFERENCE.md (✨ NEW: 500+ lines)
    ├── CHANGES_SUMMARY.md (✨ NEW: 300+ lines)
    ├── IMPLEMENTATION_SUMMARY.md (✨ NEW: 300+ lines)
    ├── SETUP_DIAGRAM.md (✨ NEW: this file)
    └── ... (existing guides)
```

## Step-by-Step Setup Process

```
1. INITIAL STATE
   ┌─────────────────┐
   │ Django Project  │
   │ (No Tenants)    │
   └─────────────────┘

2. APPLY MIGRATIONS
   $ python manage.py migrate
   
   ✓ Tables updated in main DB
   ✓ UserProfile role field updated
   ✓ Tenant model updated with status, admin_user

3. CREATE SUPERADMIN
   $ python manage.py create_superadmin
   
   Creates in Main DB:
   ┌──────────────────────────────┐
   │ User                         │
   │ ├─ username: admin@ex.com   │
   │ ├─ is_superuser: True       │
   │ └─ UserProfile              │
   │    └─ role: 'superadmin'    │
   └──────────────────────────────┘

4. SUPERADMIN LOGS IN
   $ http://localhost:8000/accounts/login/
   
   Input: admin@ex.com + password
   Output: Redirect to /tenants/superadmin/dashboard/

5. CREATE FIRST VENDOR
   Click: "Create Vendor"
   Input:
   ├─ Vendor Name: ABC Shop
   ├─ Code: abc-shop
   ├─ Email: admin@abc-shop.com
   └─ Password: vendor-password
   
   System creates:
   ┌──────────────────────┐        ┌──────────────────────┐
   │ Main Database        │        │ New Vendor Database  │
   │ ┌────────────────┐   │        │ ┌────────────────┐   │
   │ │ User           │   │        │ │ User           │   │
   │ │ - admin user   │───────────→├─│ - admin user   │   │
   │ │                │   │        │ │                │   │
   │ │ Tenant         │   │        │ │ Products       │   │
   │ │ - record       │   │        │ │ Sales          │   │
   │ │ - admin_user FK    │        │ │ Customers      │   │
   │ └────────────────┘   │        │ │ Reports        │   │
   └──────────────────────┘        │ └────────────────┘   │
                                   │ File:shop_abc-shop.  │
                                   │ sqlite3             │
                                   └──────────────────────┘

6. VENDOR ADMIN LOGS IN
   $ http://localhost:8000/accounts/login/
   
   Input: abc-shop + vendor-password
   Output: Redirect to /accounts/ (Vendor Dashboard)
   
   Session Set:
   ├─ session['tenant_id'] = 1
   ├─ session['tenant_alias'] = 'tenant_1'
   └─ All queries route to shop_abc-shop.sqlite3

7. DATA ISOLATION IN ACTION
   Product.objects.all()
         ↓
   Uses: shop_abc-shop.sqlite3
   Shows: Only ABC Shop's products
   
   (Other vendors' products not visible)

8. CREATE MORE VENDORS
   Repeat step 5
   
   ┌─────────────────────────────────────┐
   │ Main Database                       │
   │ ├─ Superadmin User                  │
   │ ├─ Vendor 1 Admin (ABC Shop)        │
   │ ├─ Vendor 2 Admin (XYZ Store)       │
   │ └─ Tenant Records: 2                │
   └─────────────────────────────────────┘
   
   ┌──────────────────┐  ┌──────────────────┐
   │ shop_abc-shop.   │  │ shop_xyz-store.  │
   │ sqlite3          │  │ sqlite3          │
   │ ─────────────    │  │ ──────────────   │
   │ ABC's data only  │  │ XYZ's data only  │
   └──────────────────┘  └──────────────────┘
```

## Request Flow Diagram

```
User Request
    │
    ▼
┌─────────────────────────────┐
│ Django Middleware           │
│ ┌─────────────────────────┐ │
│ │ TenantMiddleware        │ │
│ │ - Read session[]        │ │
│ │ - Set current_tenant()  │ │
│ └─────────────────────────┘ │
│ ┌─────────────────────────┐ │
│ │ TenantAccessMiddleware  │ │
│ │ - Check feature flags   │ │
│ └─────────────────────────┘ │
└──────────────┬──────────────┘
               │
               ▼
        ┌──────────────┐
        │ View Logic   │
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │ ORM Queries  │
        │ (Models)     │
        └──────┬───────┘
               │
               ▼
        ┌────────────────────┐
        │ Database Router    │
        │ get_current_tenant │
        │ determine DB alias │
        └────────┬───────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
    ┌────────┐        ┌──────────┐
    │ Main   │        │ Tenant   │
    │ DB     │        │ DB       │
    │default │        │tenant_1  │
    └────────┘        └──────────┘
```

## Control Flow During Vendor Creation

```
Superadmin @ /tenants/superadmin/create-vendor/
    │
    ├─ Validate Form
    │  ├─ Unique vendor_code?
    │  ├─ Unique email?
    │  └─ Passwords match?
    │
    ├─ Create Admin User in Main DB
    │  ├─ User.objects.create_user()
    │  └─ UserProfile.objects.create(role='admin')
    │
    ├─ Create Tenant Record in Main DB
    │  ├─ Tenant.objects.create()
    │  ├─ name, code, owner_email
    │  └─ admin_user FK link
    │
    ├─ Provision Vendor Database
    │  └─ Create empty: tenant_dbs/shop_{code}.sqlite3
    │
    ├─ Migrate Vendor Database
    │  ├─ Run: makemigrations
    │  └─ Run: migrate --database=tenant_X
    │
    └─ Create Admin User in Vendor DB
       ├─ UserModel.objects.db_manager(db_alias).create_user()
       └─ UserProfile.objects.using(db_alias).create(role='admin')
    
    Result: ✓ Vendor Ready to Login
```

## Permission Matrix in Action

```
URL Request: /inventory/products/

                Superadmin   Vendor Admin    Staff      Customer
                ──────────   ────────────    ─────      ────────
1. Middleware   PASS         PASS            PASS       FAIL
   Check Auth   (if logged)  (if logged)     (if logged) (redirect)
                
2. Tenant       PASS*        PASS            PASS       N/A
   Context      (logged out) (vendor_id=1)   (vendor_id=1)
                
3. Access       access_      access_         access_    DENIED
   Control      inventory=?  inventory=True  inventory=?
                (if enabled) (default)       (if enabled)
                
4. Query        Uses Main    Uses Tenant     Uses Tenant N/A
   Database     DB or        DB Only         DB Only
                Tenant DB

* Superadmin needs explicit tenant context to access vendor data
```

## Session State Tracking

```
Session States Throughout User Journey

STATE 1: Fresh Login Page
┌──────────────────────────┐
│ request.session          │
│ └─ (empty)               │
└──────────────────────────┘

STATE 2: Superadmin Logs In
┌──────────────────────────┐
│ request.session          │
│ ├─ _auth_user_id: 1      │
│ ├─ _auth_user_hash: xxx  │
│ └─ (tenant_id removed)   │
└──────────────────────────┘

STATE 3: Vendor Admin Logs In
┌──────────────────────────┐
│ request.session          │
│ ├─ _auth_user_id: 2      │
│ ├─ _auth_user_hash: xxx  │
│ ├─ tenant_id: 1          │  ← Vendor Context
│ └─ tenant_alias: tenant_1│  ← DB Alias
└──────────────────────────┘

STATE 4: Superadmin Switches to Vendor View
┌──────────────────────────┐
│ request.session          │
│ ├─ _auth_user_id: 1      │
│ ├─ _auth_user_hash: xxx  │
│ ├─ tenant_id: 1          │  ← Vendor Context
│ ├─ tenant_alias: tenant_1│  ← DB Alias
│ └─ superadmin_id: 1      │  ← Track superadmin
└──────────────────────────┘

STATE 5: User Logs Out
┌──────────────────────────┐
│ request.session          │
│ └─ (cleared)             │
└──────────────────────────┘
```

## Database Connection Pool

```
Django Settings.DATABASES

┌─────────────────────────────────────────┐
│ 'default'                               │
│ {                                       │
│   'ENGINE': 'django.db.backends.sqlite3'│
│   'NAME': 'db.sqlite3'                  │
│ }                                       │
│                                         │
│ 'tenant_1'                              │ ← Dynamic
│ {                                       │
│   'ENGINE': 'django.db.backends.sqlite3'│
│   'NAME': 'tenant_dbs/shop_code1.db'   │
│ }                                       │
│                                         │
│ 'tenant_2'                              │ ← Dynamic
│ {                                       │
│   'ENGINE': 'django.db.backends.sqlite3'│
│   'NAME': 'tenant_dbs/shop_code2.db'   │
│ }                                       │
│                                         │
│ ... (one per vendor)                    │
└─────────────────────────────────────────┘

Created by: ensure_tenant_db()
Stored in: Django connections.databases
Cached for request duration
```

---

## Quick Reference Table

| Component | Location | Purpose | Status |
|-----------|----------|---------|--------|
| Superadmin Views | tenants/views.py | Vendor management | ✨ NEW |
| Superadmin URLs | tenants/urls.py | Route superadmin | ✨ NEW |
| Create Command | accounts/mgmt/commands/ | Bootstrap system | ✨ NEW |
| Dual Auth | accounts/views.py | Super+Vendor login | ✏️ UPDATED |
| Tenant Model | tenants/models.py | Vendor definition | ✏️ UPDATED |
| User Roles | accounts/models.py | Superadmin role | ✏️ UPDATED |
| URL Config | shop_management/urls.py | Route tenants | ✏️ UPDATED |
| Middleware | tenants/middleware.py | Context mgmt | (existing) |
| DB Router | tenants/db_router.py | Route queries | (existing) |

---

This completes the multi-tenant implementation!

**Next Steps:**
1. Run migrations: `python manage.py migrate`
2. Create superadmin: `python manage.py create_superadmin`
3. Start server: `python manage.py runserver`
4. Visit: `http://localhost:8000/accounts/login/`
5. Create vendors from superadmin dashboard
