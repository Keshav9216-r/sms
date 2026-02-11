# 🛍️ Django Shop Management System - Complete Setup Guide

## For Stationery Shop (Books + Stationery Items)

---

## 📋 PROJECT OVERVIEW

This is a **complete shop management system** with:
- ✅ Product Management (Stationery & Books)
- ✅ Vendor Database
- ✅ Inventory Management
- ✅ Customer Database (Mobile as primary key)
- ✅ Credit Tracking System
- ✅ POS/Billing System
- ✅ Receipt Generation (PDF & Printable)
- ✅ Barcode Generation
- ✅ Admin Login Portal
- ✅ Sales Reports

---

## 🔧 INSTALLATION STEPS

### Step 1: Install Python & Required Tools

```bash
# Windows: Download Python from python.org (3.9 or higher)
# Linux/Mac:
sudo apt-get install python3 python3-pip python3-venv

# Install MySQL
# Windows: Download from mysql.com
# Linux:
sudo apt-get install mysql-server mysql-client

# Create Virtual Environment
python -m venv shop_env

# Activate Virtual Environment
# Windows:
shop_env\Scripts\activate
# Linux/Mac:
source shop_env/bin/activate
```

### Step 2: Create Django Project

```bash
# Install Django & Dependencies
pip install -r requirements.txt

# Create Django Project
django-admin startproject shop_management .

# Create Django Apps
python manage.py startapp accounts      # User authentication
python manage.py startapp inventory     # Products & Stock
python manage.py startapp vendors       # Vendor management
python manage.py startapp customers     # Customer records
python manage.py startapp sales         # Billing & Orders
python manage.py startapp reports       # Reports & Analytics
```

### Step 3: MySQL Database Setup

```bash
# Login to MySQL
mysql -u root -p

# Create Database
CREATE DATABASE shop_management;
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 4: Configure Django Settings

**Update `settings.py`:**
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'shop_management',
        'USER': 'shop_user',
        'PASSWORD': '<set-strong-password>',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}
```

### Step 5: Run Migrations & Create Superuser

```bash
# Create Database Tables
python manage.py makemigrations
python manage.py migrate

# Create Admin User
python manage.py createsuperuser
# Username: admin
# Email: admin@shop.com
# Password: <set-strong-password>

# Load Sample Data (Optional)
python manage.py loaddata sample_data.json
```

### Step 6: Run Development Server

```bash
python manage.py runserver
# Access at: http://localhost:8000/admin
```

---

## 📁 PROJECT STRUCTURE

```
shop_management/
├── manage.py
├── requirements.txt
├── shop_management/
│   ├── settings.py          # Database & App configuration
│   ├── urls.py              # Main URL routing
│   ├── wsgi.py
│   └── asgi.py
│
├── accounts/                # User Authentication
│   ├── models.py           # User model
│   ├── views.py            # Login/Logout views
│   ├── urls.py
│   └── templates/
│       ├── login.html
│       ├── register.html
│       └── dashboard.html
│
├── inventory/              # Products & Stock
│   ├── models.py           # Product, Category, Inventory models
│   ├── views.py            # Product management views
│   ├── urls.py
│   └── templates/
│       ├── products_list.html
│       ├── product_add.html
│       └── inventory_view.html
│
├── vendors/                # Vendor Management
│   ├── models.py           # Vendor, PurchaseOrder models
│   ├── views.py
│   ├── urls.py
│   └── templates/
│       ├── vendors_list.html
│       ├── vendor_add.html
│       └── purchase_orders.html
│
├── customers/              # Customer Database
│   ├── models.py           # Customer, Credit models
│   ├── views.py
│   ├── urls.py
│   └── templates/
│       ├── customers_list.html
│       ├── customer_add.html
│       └── credit_history.html
│
├── sales/                  # POS & Billing
│   ├── models.py           # Sale, SaleItem models
│   ├── views.py            # POS views
│   ├── urls.py
│   ├── utils.py            # PDF & Receipt generation
│   └── templates/
│       ├── pos.html        # Main POS interface
│       ├── receipt.html    # Receipt template
│       └── transaction_history.html
│
├── reports/                # Reports & Analytics
│   ├── views.py
│   ├── urls.py
│   └── templates/
│       ├── sales_report.html
│       ├── inventory_report.html
│       └── customer_report.html
│
└── static/
    ├── css/
    │   └── style.css
    ├── js/
    │   └── main.js
    └── images/
```

---

## 🚀 DEPLOYMENT (Immediate)

### Option 1: PythonAnywhere (Recommended for Beginners)

1. Go to pythonanywhere.com
2. Sign up (free account available)
3. Upload your Django project
4. Configure MySQL database
5. Set web app configuration
6. Deploy immediately!

### Option 2: Local Network (LAN)

1. Note your computer's IP address: `ipconfig` (Windows) or `ifconfig` (Linux)
2. Run: `python manage.py runserver 0.0.0.0:8000`
3. Access from other computers: `http://YOUR_IP:8000`

### Option 3: AWS / DigitalOcean (Production)

Instructions provided in deployment guide below.

---

## 📱 KEY FEATURES EXPLAINED

### 1. User Authentication
- Admin login portal
- Role-based access (Admin/Staff)
- Secure password hashing
- Session management

### 2. Product Management
- Add/Edit/Delete products
- Categorize (Stationery/Books)
- Barcode generation
- Cost & Selling price tracking

### 3. Inventory System
- Real-time stock tracking
- Low stock alerts
- Stock adjustment
- Purchase order management

### 4. Customer Database
- Register customers with mobile number (Nepal format)
- Credit limit tracking
- Payment history
- Purchase history

### 5. POS System
- Quick product search (barcode/name)
- Add items to cart
- Discount & tax calculation
- Receipt generation (PDF/Print)

### 6. Reporting
- Sales reports (daily/weekly/monthly)
- Inventory reports
- Customer credit reports
- Export to Excel/PDF

---

## 🔐 Security Features

✅ Password hashing (bcrypt)
✅ CSRF protection
✅ SQL injection prevention
✅ Session management
✅ Login required decorators
✅ User permission system

---

## 💡 TIPS FOR BEGINNERS

1. **Always activate virtual environment** before running commands
2. **Create superuser immediately** after migrations
3. **Test locally first** before deploying
4. **Backup database regularly** using: `python manage.py dumpdata > backup.json`
5. **Check error logs** when something goes wrong
6. **Use Django admin** at `/admin` for quick testing

---

## ⚠️ COMMON ISSUES & SOLUTIONS

**Issue:** `ModuleNotFoundError: No module named 'django'`
**Solution:** `pip install -r requirements.txt` and activate virtual environment

**Issue:** `MySQL connection error`
**Solution:** Check MySQL is running, username/password correct in settings.py

**Issue:** `Port 8000 already in use`
**Solution:** `python manage.py runserver 8001` (use different port)

**Issue:** `Static files not loading`
**Solution:** Run `python manage.py collectstatic`

---

## 📞 SUPPORT

- Django Docs: https://docs.djangoproject.com
- Stack Overflow: Search your error message
- Django Forum: https://forum.djangoproject.com

---

## ✅ NEXT STEPS

1. Install all requirements using provided requirements.txt
2. Follow installation steps above
3. Copy all model files into respective apps
4. Run migrations
5. Create superuser
6. Access admin panel and start using!

**You're ready to go! 🚀**
