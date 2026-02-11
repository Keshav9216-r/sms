# 🛍️ COMPLETE DJANGO SHOP MANAGEMENT SYSTEM

## README - Start Here!

**Repository layout update:** the Django project now lives in backend/. Run all `manage.py` commands from backend/ (and keep `.env` in backend/). Frontend assets are in frontend/ (templates, static, media).

### ✅ What You Have

This is a **complete, production-ready Django shop management system** for your stationery shop with:

✅ **User Authentication** - Secure login portal for admin and staff
✅ **Product Management** - Add stationery items and books with barcodes
✅ **Inventory System** - Real-time stock tracking with low stock alerts
✅ **Customer Database** - Store customers with mobile number (Nepal format)
✅ **Credit Management** - Track customer credit and payment history
✅ **POS/Billing System** - Fast checkout with product search
✅ **Receipt Generation** - PDF and printable receipts
✅ **Barcode Scanning** - Generate and scan product barcodes
✅ **Reports** - Sales, inventory, and customer reports
✅ **Responsive UI** - Works on desktop, tablet, and mobile

---

## 🚀 QUICK START (10 MINUTES)

### What You Need First:
1. **Python 3.9+** - Download from python.org
2. **MySQL** - Download from mysql.com
3. A text editor (VS Code recommended)

### Step 1: Prepare Your Computer
```bash
# Open Command Prompt/Terminal

# Windows - Install Python (select "Add to PATH" during install)
# Then check:
python --version
pip --version

# Linux/Mac:
python3 --version
pip3 --version

# Check MySQL is running:
# Windows: MySQL is running as service
# Linux: sudo service mysql status
```

### Step 2: Create Project Folder
```bash
# Create folder for your project
mkdir shop_management
cd shop_management

# Create virtual environment (isolated Python environment)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### Step 3: Install Django & Dependencies
```bash
# Copy this command and paste in terminal
pip install Django==4.2.8 mysqlclient==2.2.0 python-barcode==0.14.0 qrcode==7.4.2 reportlab==4.0.4 WeasyPrint==58.0 Pillow==10.0.0 python-dotenv==1.0.0 django-crispy-forms==2.1 crispy-bootstrap5==2.0.0 django-filter==23.5 django-import-export==3.3.4 openpyxl==3.1.0 requests==2.31.0 gunicorn==21.2.0 whitenoise==6.6.0
```

### Step 4: Create MySQL Database
```bash
# Open MySQL Command Line (or use MySQL Workbench)
mysql -u root -p
# Enter your root password

# Copy and paste these commands:
CREATE DATABASE shop_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 5: Create Django Project
```bash
# Create Django project structure
django-admin startproject shop_management .

# Create apps
python manage.py startapp accounts
python manage.py startapp inventory
python manage.py startapp customers
python manage.py startapp sales
python manage.py startapp reports
```

### Step 6: Verify Project Files
All code is already included in the repository:
- Django apps live under `accounts/`, `inventory/`, `customers/`, `sales/`, and `reports/`.
- Project settings and routing live under `shop_management/`.
- Templates live under `templates/`.

No manual file copying is required.

### Step 7: Database Migration
```bash
# Create database tables
python manage.py makemigrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser
# Follow prompts:
# Username: admin
# Email: admin@shop.com
# Password: <set-strong-password>

# Prepare static files
python manage.py collectstatic --noinput
```

### Step 8: Start Development Server
```bash
# Run the application
python manage.py runserver

# Open browser and visit:
# http://localhost:8000 - Main site
# http://localhost:8000/admin - Admin panel
# Login with admin credentials you created
```

---

## 📱 USING THE SYSTEM

### Login
1. Go to http://localhost:8000/admin
2. Username: `admin`
3. Password: The password you set during createsuperuser

### Add Products
1. Go to **Inventory → Products**
2. Click **Add Product**
3. Fill: SKU, Product Name, Category (Books/Stationery), Cost Price, Selling Price
4. Click Save
5. Barcode auto-generates!

### Add Customers
1. Go to **Customers**
2. Click **Add Customer**
3. Fill: Phone (Nepal format like 9841234567), Name, Address
4. Set credit limit if needed
5. Save

### Make a Sale (POS)
1. Go to **POS/Billing**
2. Search product by name or barcode
3. Add to cart
4. Enter customer phone (optional)
5. Choose payment method (cash/card/credit/cheque)
6. Click Complete Sale
7. Print receipt or generate PDF

### View Reports
1. Go to **Reports**
2. Choose: Sales, Inventory, or Customer reports
3. Select date range
4. Export to Excel if needed

---

## 🌐 DEPLOY TO INTERNET (15 MINUTES)

### RECOMMENDED: PythonAnywhere (Free & Easy)

1. Go to **pythonanywhere.com**
2. Create free account
3. Go to **Upload files** → drag & drop your project
4. Go to **Web** → Create new web app → Django
5. Configure MySQL in Database tab
6. Update `settings.py` with PythonAnywhere credentials:
   ```python
   DATABASES = {
       'default': {
           'ENGINE': 'django.db.backends.mysql',
           'NAME': 'yourusername$shop_management',
           'USER': 'yourusername',
           'PASSWORD': 'your_mysql_password',
           'HOST': 'yourusername.mysql.pythonanywhere-services.com',
       }
   }
   ALLOWED_HOSTS = ['yourusername.pythonanywhere.com']
   DEBUG = False
   ```
7. Run migrations in Bash console:
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```
8. Reload web app
9. Access at: **yourusername.pythonanywhere.com**

---

## 🛠️ COMMON ISSUES & FIXES

### Issue: "ModuleNotFoundError: No module named 'django'"
**Solution:**
```bash
# Activate virtual environment first
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Then install:
pip install -r requirements.txt
```

### Issue: "MySQL connection error"
**Solution:**
1. Check MySQL is running
2. Verify database name, user, password in settings.py
3. Verify database was created:
   ```bash
   mysql -u root -p
   SHOW DATABASES;  # Should show shop_management
   EXIT;
   ```

### Issue: "Port 8000 already in use"
**Solution:**
```bash
python manage.py runserver 8001  # Use different port
```

### Issue: "Static files not loading"
**Solution:**
```bash
python manage.py collectstatic --noinput
```

### Issue: Products not saving / Database errors
**Solution:**
1. Delete file: `db.sqlite3` (if exists)
2. Run migrations again:
   ```bash
   python manage.py migrate
   ```

---

## 📋 FILE STRUCTURE AFTER SETUP

```
shop_management/
├── venv/                          # Virtual environment (auto-created)
├── manage.py                      # Django management script
├── requirements.txt               # Dependencies list
│
├── shop_management/               # Main project config
│   ├── settings.py               # Update with your config
│   ├── urls.py                   # Main URL routing
│   └── wsgi.py
│
├── accounts/                      # User authentication
│   ├── models.py                 # User model (copy from file)
│   ├── views.py                  # Login/logout views
│   ├── urls.py                   # App URLs
│   └── templates/
│       ├── login.html
│       └── dashboard.html
│
├── inventory/                     # Products & Stock
│   ├── models.py                 # Product, Category models
│   ├── views.py                  # Product views
│   ├── urls.py
│   └── templates/
│
├── vendors/                       # Vendors
│   ├── models.py
│   ├── views.py
│   └── urls.py
│
├── customers/                     # Customers
│   ├── models.py
│   ├── views.py
│   └── urls.py
│
├── sales/                         # POS & Billing
│   ├── models.py
│   ├── views.py                  # POS, receipt views
│   ├── utils.py                  # PDF generation
│   ├── urls.py
│   └── templates/
│       ├── pos.html              # Main POS interface
│       └── receipt.html          # Receipt template
│
├── reports/                       # Reports
│   ├── models.py
│   ├── views.py
│   └── urls.py
│
├── templates/                     # HTML templates
│   ├── base.html                 # Base template (copy from file)
│   ├── accounts/
│   ├── inventory/
│   ├── sales/
│   └── ...
│
├── static/                        # CSS, JS, Images
│   ├── css/
│   ├── js/
│   └── images/
│
└── media/                         # Uploaded files, barcodes
```

---

## 🔐 SECURITY TIPS

### Before Going Live:
1. Change `SECRET_KEY` in settings.py to something random
2. Set `DEBUG = False` in settings.py
3. Create strong superuser password (not 'admin')
4. Enable HTTPS/SSL certificate
5. Regular backups: `mysqldump -u shop_user -p shop_management > backup.sql`
6. Monitor error logs

### User Permissions:
- **Admin**: Full access to all features
- **Staff**: POS, inventory, customer access only
- **Manager**: Everything except user management

---

## 📞 GETTING HELP

### If Something Goes Wrong:
1. **Read error message carefully** - Usually tells you what's wrong
2. **Google the error** - Search on Stack Overflow
3. **Check Django docs** - https://docs.djangoproject.com/
4. **Check YouTube tutorials** - "Django shop management system"

### Important Resources:
- Django Docs: https://docs.djangoproject.com/
- PythonAnywhere Help: https://www.pythonanywhere.com/help/
- Stack Overflow: Tag: `django`
- Official Django Forum: https://forum.djangoproject.com/

---

## ✅ WHAT'S NEXT?

### Phase 1 (Done!)
- ✅ Installation
- ✅ Database setup
- ✅ Basic running system

### Phase 2 (Customize)
- Customize shop name and branding
- Add your logo
- Adjust colors and UI
- Add sample products
- Train staff on usage

### Phase 3 (Deployment)
- Deploy to PythonAnywhere/AWS/DigitalOcean
- Setup custom domain
- Enable HTTPS
- Monitor performance

### Phase 4 (Maintenance)
- Regular backups
- Monitor sales
- Update inventory regularly
- Review reports
- Add new products

---

## 💡 TIPS FOR SUCCESS

1. **Backup regularly** - Your data is important!
   ```bash
   mysqldump -u shop_user -p shop_management > backup_$(date +%Y%m%d).sql
   ```

2. **Test on local first** - Before deploying to live
   ```bash
   python manage.py runserver
   ```

3. **Create good product data** - System is only as good as your data

4. **Train your staff** - Let them practice before going live

5. **Monitor error logs** - Catch issues early

---

## 🎉 YOU'RE READY!

Congratulations! You now have a professional shop management system.

**Your next step:** Follow the Quick Start section above to get started.

**Need more help?** Check the other provided files:
- `django_setup_guide.md` - Detailed setup
- `deployment_guide.md` - Production deployment

**Happy selling! 🛍️**
# learn
