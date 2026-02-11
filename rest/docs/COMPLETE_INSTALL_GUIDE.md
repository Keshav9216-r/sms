# 🚀 COMPLETE INSTALLATION GUIDE - FROM SCRATCH TO RUNNING

## For Windows, Linux, and Mac Users

---

## PART 1: PREREQUISITES (What You Need to Download First)

### For Windows Users:

**Step 1: Download Python**
1. Go to https://www.python.org/downloads/
2. Click "Download Python 3.11" (or latest 3.9+)
3. Run the installer
4. ⚠️ **IMPORTANT:** Check the box "Add Python to PATH" ✓
5. Click "Install Now"
6. Wait for installation to complete
7. Click "Close"

**Step 2: Download MySQL**
1. Go to https://dev.mysql.com/downloads/mysql/
2. Select Windows installer (32-bit or 64-bit - match your computer)
3. Click "Download" 
4. Run the installer
5. Click "Next" through setup
6. Choose "MySQL Server" and "MySQL Workbench"
7. Configure as "Development Machine"
8. Port: 3306 (default)
9. Username: root
10. Password: Create a password (remember this!)
11. Complete installation

**Step 3: Download Git (Optional but Recommended)**
1. Go to https://git-scm.com/download/win
2. Run installer
3. Click "Next" for all options
4. Complete installation

**Verify Installation Works:**
```bash
# Open Command Prompt (Press Windows Key + R, type "cmd", press Enter)
python --version       # Should show Python 3.9+ or 3.11+
pip --version          # Should show pip version
mysql --version        # Should show MySQL version
```

---

### For Linux Users (Ubuntu/Debian):

```bash
# Open Terminal
# Install Python
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv

# Install MySQL
sudo apt-get install mysql-server mysql-client libmysqlclient-dev

# Install Git (optional)
sudo apt-get install git

# Verify installation
python3 --version
pip3 --version
mysql --version
```

---

### For Mac Users:

```bash
# Option 1: Using Homebrew (recommended)
# First install Homebrew: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python3
brew install mysql
brew install git

# Option 2: Download installers from:
# - Python: https://www.python.org/downloads/
# - MySQL: https://dev.mysql.com/downloads/mysql/

# Verify installation
python3 --version
pip3 --version
mysql --version
```

---

## PART 2: CREATE PROJECT FOLDER & SETUP (10 MINUTES)

### Step 1: Create Project Directory

**Windows (Command Prompt):**
```bash
# Create folder
mkdir C:\shop_management
cd C:\shop_management

# Or create anywhere you want, then navigate there
cd Desktop
mkdir shop_management
cd shop_management
```

**Linux/Mac (Terminal):**
```bash
# Create folder in home directory
mkdir ~/shop_management
cd ~/shop_management

# Or in Desktop
mkdir ~/Desktop/shop_management
cd ~/Desktop/shop_management
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment (you'll see (venv) at start of line)
venv\Scripts\activate
```

**Linux/Mac:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

**What You'll See:**
```
(venv) C:\shop_management>    # Windows
(venv) ~/shop_management$     # Linux/Mac
```

✅ **Good!** Virtual environment is active. Now all installations are isolated.

### Step 3: Create requirements.txt File

**Windows (Using Notepad):**
1. Right-click in the folder
2. Select "New" → "Text Document"
3. Name it "requirements.txt"
4. Copy-paste this content:

```
Django==4.2.8
mysqlclient==2.2.0
python-barcode==0.14.0
qrcode==7.4.2
reportlab==4.0.4
WeasyPrint==58.0
Pillow==10.0.0
python-dotenv==1.0.0
django-crispy-forms==2.1
crispy-bootstrap5==2.0.0
django-filter==23.5
django-import-export==3.3.4
openpyxl==3.1.0
requests==2.31.0
gunicorn==21.2.0
whitenoise==6.6.0
```

**Linux/Mac (Using Terminal):**
```bash
cat > requirements.txt << 'EOF'
Django==4.2.8
mysqlclient==2.2.0
python-barcode==0.14.0
qrcode==7.4.2
reportlab==4.0.4
WeasyPrint==58.0
Pillow==10.0.0
python-dotenv==1.0.0
django-crispy-forms==2.1
crispy-bootstrap5==2.0.0
django-filter==23.5
django-import-export==3.3.4
openpyxl==3.1.0
requests==2.31.0
gunicorn==21.2.0
whitenoise==6.6.0
EOF
```

### Step 4: Install All Python Packages

```bash
# This will take 2-3 minutes
pip install -r requirements.txt

# Wait for "Successfully installed" message
```

⏳ **Be Patient!** First installation takes a few minutes as it downloads all packages.

---

## PART 3: CREATE DJANGO PROJECT (5 MINUTES)

### Step 1: Create Django Project Structure

```bash
# Make sure virtual environment is activated
# You should see (venv) at start of line

# Create main Django project
django-admin startproject shop_management .

# Create individual apps
python manage.py startapp accounts
python manage.py startapp inventory
python manage.py startapp customers
python manage.py startapp sales
python manage.py startapp reports
```

### Step 2: Verify Project Structure

You should now have folders like:
```
shop_management/
├── venv/                    # Virtual environment
├── shop_management/         # Main project folder
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── accounts/                # App folders
├── inventory/
├── customers/
├── sales/
├── reports/
├── manage.py
└── requirements.txt
```

---

## PART 4: CREATE MYSQL DATABASE (5 MINUTES)

### Windows Users:

**Option A: Using Command Prompt**
```bash
# Open new Command Prompt window (keep virtual environment window open)
mysql -u root -p

# Enter your root password (from MySQL installation)
# You'll see: mysql>

# Copy-paste these commands:
CREATE DATABASE shop_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Back to regular prompt
```

**Option B: Using MySQL Workbench**
1. Open MySQL Workbench
2. Click "+" to create new connection
3. Name: `shop_management`
4. Username: `root`
5. Password: Your MySQL password
6. Click "Test Connection" → "OK" → "Close"
7. Double-click connection to open
8. Click "Create a new schema" icon (top toolbar)
9. Name: `shop_management`
10. Charset: `utf8mb4`
11. Click "Apply"
12. In query editor, paste:
```sql
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
```

### Linux/Mac Users:

```bash
# Open Terminal
mysql -u root

# Or with password:
mysql -u root -p

# Copy-paste these commands:
CREATE DATABASE shop_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

✅ **Database created!** You now have:
- Database name: `shop_management`
- Username: `shop_user`
- Password: the one you set above

---

## PART 5: CONFIRM SOURCE CODE IS PRESENT (2 MINUTES)

All source files are already included in this repository. You do not need to copy any code or templates from separate files.

Quick sanity check:
- Django apps exist under accounts, inventory, customers, sales, and reports.
- Project settings and routing exist under shop_management.
- Templates exist under templates.

---

## PART 6: RUN DATABASE MIGRATIONS (3 MINUTES)

**Go back to your terminal with virtual environment active:**

```bash
# Make sure (venv) shows at start of line
# If not, activate it:
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

# Create database tables
python manage.py makemigrations

# You should see output like:
# Creating migrations for:
# - accounts
# - inventory
# - customers
# - sales

# Apply migrations to database
python manage.py migrate

# You should see:
# Running migrations:
# Applying contenttypes.0001_initial...
# Applying auth.0001_initial...
# ... many more lines ...
# (venv) C:\shop_management>
```

✅ **Database tables created!**

---

## PART 7: CREATE SUPERUSER (ADMIN ACCOUNT)

```bash
# Still in terminal with (venv) active
python manage.py createsuperuser

# You'll be asked:
# Username: admin
# Email address: admin@shop.com
# Password: <set-strong-password>
# Password (again): <set-strong-password>
# Superuser created successfully.
```

✅ **Admin account created!** Remember your password.

---

## PART 8: COLLECT STATIC FILES

```bash
# Still in terminal with (venv) active
python manage.py collectstatic --noinput

# You should see:
# ...
# 123 static files copied to '.../staticfiles'
```

---

## PART 9: START THE SERVER & TEST (1 MINUTE)

```bash
# Still in terminal with (venv) active
python manage.py runserver

# You should see:
# Starting development server at http://127.0.0.1:8000/
# Quit the server with CONTROL-C.
```

✅ **Server is running!** Keep this window open.

---

## PART 10: OPEN IN BROWSER & LOGIN

1. **Open your web browser** (Chrome, Firefox, Safari, Edge)
2. **Go to:** http://localhost:8000/admin/
3. **Login with:**
   - Username: `admin`
   - Password: (whatever you set in step 7)
4. **Click "Log In"**

✅ **You're in!** You should see Django admin panel.

---

## PART 11: ACCESS YOUR SHOP SYSTEM

### Go to these URLs:

| URL | What It Does |
|-----|-------------|
| http://localhost:8000/ | Dashboard |
| http://localhost:8000/admin/ | Admin Panel |
| http://localhost:8000/inventory/products/ | Product List |
| http://localhost:8000/sales/pos/ | POS System |
| http://localhost:8000/customers/ | Customer List |
| http://localhost:8000/reports/ | Reports |

---

## PART 12: ADD YOUR FIRST PRODUCT

1. Go to Admin Panel: http://localhost:8000/admin/
2. Click "Products"
3. Click "Add Product"
4. Fill in:
   - SKU: `STAT001`
   - Product Name: `Notebook A4`
   - Category: Create new or select
   - Cost Price: `100`
   - Selling Price: `150`
5. Click "Save"

✅ **Product added!**

---

## PART 13: CREATE CATEGORY

1. In Admin Panel, click "Categories"
2. Click "Add Category"
3. Name: `Stationery`
4. Category Type: Select `stationery`
5. Click "Save"

---

## PART 14: ADD A CUSTOMER

1. Go to: http://localhost:8000/customers/
2. Click "Add Customer"
3. Fill in:
   - Phone: `9841234567` (Nepal format without +977)
   - Name: `Raj Sharma`
   - Address: `Kathmandu`
4. Click "Save"

---

## TROUBLESHOOTING COMMON ISSUES

### Issue 1: "ModuleNotFoundError: No module named 'django'"

**Solution:**
1. Make sure virtual environment is activated
2. You should see `(venv)` at start of line
3. Run: `pip install -r requirements.txt`

### Issue 2: "MySQL connection error"

**Solution:**
1. Check MySQL is running
2. Windows: Check Services (MySQL80 or MySQL57)
3. Linux/Mac: `sudo service mysql status`
4. Verify credentials in settings.py match database

### Issue 3: "Port 8000 already in use"

**Solution:**
```bash
# Use different port
python manage.py runserver 8001
# Then go to: http://localhost:8001
```

### Issue 4: "Static files not loading / Templates not found"

**Solution:**
```bash
# Run this command
python manage.py collectstatic --noinput
```

### Issue 5: Can't login to admin

**Solution:**
1. Did you create superuser? Run: `python manage.py createsuperuser`
2. Check username/password are correct
3. Try: username `admin`, password is what you entered

### Issue 6: "Permission denied" on Linux/Mac

**Solution:**
```bash
# Give permission to project folder
chmod -R 755 ~/shop_management
# Or
sudo chmod -R 755 ~/shop_management
```

---

## HOW TO STOP THE SERVER

**In the terminal where server is running:**

Press: **Ctrl + C** (on Windows, Linux, Mac)

You'll see:
```
KeyboardInterrupt
(venv) C:\shop_management>
```

The server is now stopped. Run `python manage.py runserver` again to restart.

---

## HOW TO RESTART THE SYSTEM TOMORROW

```bash
# Open terminal/command prompt
cd C:\shop_management        # Windows
# or
cd ~/shop_management         # Linux/Mac

# Activate virtual environment
venv\Scripts\activate        # Windows
# or
source venv/bin/activate     # Linux/Mac

# Start server
python manage.py runserver

# Go to http://localhost:8000/admin/
```

---

## NEXT STEPS

✅ **System is running locally!**

### To Deploy to Internet:

Follow the **`deployment_guide.md`** file

Easiest option: **PythonAnywhere**
1. Go to pythonanywhere.com
2. Sign up (free account)
3. Upload your code
4. Configure database
5. It's live in 15 minutes!

---

## SUMMARY

```
Installed:
✅ Python 3.9+
✅ MySQL Database
✅ Django 4.2.8
✅ All dependencies
✅ Shop Management System
✅ Superuser account
✅ Database tables

System is running at:
✅ http://localhost:8000/

Next: Deploy to PythonAnywhere for live internet access!
```

---

## 📞 NEED HELP?

1. Check **Troubleshooting** section above
2. Google the error message
3. Visit https://stackoverflow.com and search `django`
4. Ask on https://forum.djangoproject.com

**You've got this! 🎉**
