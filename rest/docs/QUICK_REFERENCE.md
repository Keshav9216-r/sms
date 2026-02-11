# ⚡ QUICK REFERENCE - COMMANDS CHEAT SHEET

## MOST IMPORTANT COMMANDS (Save This!)

### ACTIVATE VIRTUAL ENVIRONMENT (Do this first every time!)

**Windows:**
```bash
venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

✅ You'll see `(venv)` appear at start of line

---

## COMMON COMMANDS

### Start Development Server
```bash
python manage.py runserver
# Then go to: http://localhost:8000
```

### Create Database Tables
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Admin Account
```bash
python manage.py createsuperuser
```

### View Django Admin
- URL: http://localhost:8000/admin/

### Create New App
```bash
python manage.py startapp app_name
```

### Stop Server
**Press Ctrl + C** in terminal

### Deactivate Virtual Environment
```bash
deactivate
```

---

## FILE LOCATIONS

| File | Location |
|------|----------|
| Models | `app_name/models.py` |
| Views | `app_name/views.py` |
| URLs | `app_name/urls.py` |
| Templates | `templates/app_name/file.html` |
| Static Files | `static/css/`, `static/js/` |
| Settings | `shop_management/settings.py` |
| Main URLs | `shop_management/urls.py` |

---

## DATABASE BACKUP & RESTORE

### Backup
```bash
mysqldump -u shop_user -p shop_management > backup.sql
# Enter the password you set for MySQL
```

### Restore
```bash
mysql -u shop_user -p shop_management < backup.sql
# Enter the password you set for MySQL
```

---

## IMPORTANT URLS

| URL | Purpose |
|-----|---------|
| http://localhost:8000 | Homepage/Dashboard |
| http://localhost:8000/admin/ | Admin Panel |
| http://localhost:8000/inventory/products/ | Product Management |
| http://localhost:8000/sales/pos/ | POS System |
| http://localhost:8000/customers/ | Customer Database |
| http://localhost:8000/reports/ | Reports Dashboard |

---

## DEFAULT LOGIN

- **Username:** admin
- **Password:** (what you created with createsuperuser)
- **URL:** http://localhost:8000/admin/

---

## DATABASE CREDENTIALS

- **Database:** shop_management
- **User:** shop_user
- **Password:** the one you set during MySQL setup
- **Host:** localhost
- **Port:** 3306

---

## PYTHON DEPENDENCIES (Already Installed)

```
Django 4.2.8
MySQL Client
Barcode Generator
QR Code Generator
PDF Report Lab
Crispy Forms (Bootstrap)
Django Filter
Django Import/Export
Gunicorn (for production)
White Noise (for static files)
```

---

## QUICK TROUBLESHOOTING

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: django` | Activate virtual environment, run `pip install -r requirements.txt` |
| `MySQL connection error` | Check MySQL running, verify credentials in settings.py |
| `Port 8000 already in use` | Use `python manage.py runserver 8001` |
| `Static files not loading` | Run `python manage.py collectstatic --noinput` |
| `Can't login to admin` | Create superuser: `python manage.py createsuperuser` |
| `Templates not found` | Check `templates/` folder exists and is in TEMPLATES in settings.py |

---

## DIRECTORY STRUCTURE (After Installation)

```
shop_management/
├── venv/                        ← Virtual environment
├── manage.py                    ← Django command script
├── requirements.txt             ← Dependencies list
├── shop_management/             ← Main project folder
│   ├── settings.py             ← Database config
│   ├── urls.py                 ← Main URLs
│   ├── wsgi.py
│   └── asgi.py
├── accounts/                   ← User app
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   └── templates/accounts/
├── inventory/                  ← Products app
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   └── templates/inventory/
├── customers/                  ← Customer app
├── sales/                      ← POS app
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── utils.py               ← PDF generation
│   └── templates/sales/
├── reports/                    ← Reports app
├── templates/                  ← HTML templates
│   ├── base.html
│   ├── accounts/
│   ├── inventory/
│   ├── sales/
│   └── customers/
├── static/                     ← CSS, JS, Images
│   ├── css/
│   ├── js/
│   └── images/
├── staticfiles/                ← Collected static files (auto-created)
└── media/                      ← Uploaded files, barcodes
```

---

## FIRST TIME SETUP CHECKLIST

- [ ] Python installed (python --version)
- [ ] MySQL installed and running
- [ ] Project folder created
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (pip install -r requirements.txt)
- [ ] MySQL database created
- [ ] Django project created
- [ ] Model files copied
- [ ] Settings.py updated
- [ ] URLs configured
- [ ] Migrations run (python manage.py migrate)
- [ ] Superuser created (python manage.py createsuperuser)
- [ ] Server started (python manage.py runserver)
- [ ] Can access http://localhost:8000/admin/
- [ ] Can login with admin credentials
- [ ] Can add products
- [ ] Can add customers

---

## DAILY WORKFLOW

### Morning (Start Fresh)
```bash
# 1. Open terminal/command prompt
# 2. Navigate to project folder
cd C:\shop_management          # Windows
# or
cd ~/shop_management           # Linux/Mac

# 3. Activate virtual environment
venv\Scripts\activate          # Windows
# or
source venv/bin/activate       # Linux/Mac

# 4. Start server
python manage.py runserver

# 5. Open browser
# Go to: http://localhost:8000/admin/
```

### Evening (Shut Down)
```bash
# In terminal where server runs:
# Press: Ctrl + C

# Deactivate virtual environment:
deactivate
```

---

## USEFUL DJANGO COMMANDS

```bash
# Makemigrations (prepare changes)
python manage.py makemigrations

# Apply migrations (apply changes to database)
python manage.py migrate

# Create superuser (admin account)
python manage.py createsuperuser

# Change password
python manage.py changepassword username

# Create new app
python manage.py startapp app_name

# Collect static files (for production)
python manage.py collectstatic --noinput

# Run server on different port
python manage.py runserver 8001

# Drop into database shell
python manage.py dbshell

# Python shell with Django context
python manage.py shell

# Check for problems
python manage.py check

# Backup database
python manage.py dumpdata > backup.json

# Restore database
python manage.py loaddata backup.json
```

---

## MYSQL COMMANDS

```bash
# Connect to MySQL
mysql -u root -p

# Or with password
mysql -u root -p

# In MySQL prompt:
SHOW DATABASES;                  # List all databases
USE shop_management;             # Select database
SHOW TABLES;                     # Show all tables
DESCRIBE table_name;             # Show table structure
SELECT COUNT(*) FROM table_name; # Count records
EXIT;                            # Exit MySQL
```

---

## PYTHON PACKAGE COMMANDS

```bash
# Install single package
pip install package_name

# Install from requirements.txt
pip install -r requirements.txt

# Upgrade package
pip install --upgrade package_name

# Uninstall package
pip uninstall package_name

# List installed packages
pip list

# Check version of package
pip show package_name
```

---

## HELPFUL KEYBOARD SHORTCUTS

| Shortcut | Action |
|----------|--------|
| Ctrl + C | Stop running process (server, etc.) |
| Ctrl + L | Clear terminal screen |
| Up Arrow | Previous command |
| Tab | Auto-complete file/folder name |
| Ctrl + Shift + Esc | Open Task Manager (Windows) |

---

## FILE EDITOR TIPS

### Using VS Code (Recommended):
```bash
# Open project in VS Code
code .
```

### View File Content:
```bash
# Windows
type filename.txt

# Linux/Mac
cat filename.txt

# Or use text editor
```

---

## PERMISSIONS (Linux/Mac)

```bash
# Make file executable
chmod +x filename.py

# Make folder and contents writable
chmod -R 755 foldername

# Make file readable
chmod 644 filename.txt
```

---

## SAVE THIS CHEAT SHEET!

Print this page or bookmark it. You'll reference it often during development.

**Most Frequent Commands:**
1. `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
2. `python manage.py runserver`
3. `python manage.py migrate`
4. `python manage.py createsuperuser`

**Most Frequent URLs:**
1. http://localhost:8000/admin/
2. http://localhost:8000/
3. http://localhost:8000/sales/pos/

---

## STILL STUCK?

1. ✅ Check this cheat sheet first
2. ✅ Check COMPLETE_INSTALL_GUIDE.md troubleshooting
3. ✅ Google the error message
4. ✅ Visit Stack Overflow
5. ✅ Check Django documentation

**You've got this! 💪**
