# DEPLOYMENT GUIDE - Deploy Django Shop Management System

## 🚀 QUICK START - Local Deployment (5 minutes)

### Prerequisites:
- Python 3.9+
- MySQL installed and running
- Git (optional)

### Step-by-Step Installation:

```bash
# 1. Create project folder
mkdir shop_management
cd shop_management

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Configure environment
# Copy the example file and update values for your environment.
cp backend/.env.example backend/.env

# Required values:
# - SECRET_KEY
# - ALLOWED_HOSTS
# - DB_ENGINE and DB_* settings
# - CSRF_TRUSTED_ORIGINS for HTTPS domains

# 6. Create Django project & apps
django-admin startproject shop_management .
python manage.py startapp accounts
python manage.py startapp inventory
python manage.py startapp vendors
python manage.py startapp customers
python manage.py startapp sales
python manage.py startapp reports

# 7. Create MySQL database
mysql -u root -p
# Run these commands in MySQL:
CREATE DATABASE shop_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shop_user'@'localhost' IDENTIFIED BY '<set-strong-password>';
GRANT ALL PRIVILEGES ON shop_management.* TO 'shop_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# 8. Confirm source code is present
# All apps, settings, URLs, and templates are already included in this repository.
# No manual copy steps are required.

# 9. Run migrations
python manage.py makemigrations
python manage.py migrate

# 10. Create superuser
python manage.py createsuperuser
# Username: admin
# Email: admin@shop.com
# Password: <set-strong-password>

# 11. Collect static files (for production)
python manage.py collectstatic

# 12. Run development server
python manage.py runserver

# Access at: http://localhost:8000
# Admin panel: http://localhost:8000/admin
```

---

## 🌐 DEPLOYMENT OPTIONS

### Option 1: PythonAnywhere (RECOMMENDED FOR BEGINNERS)

**Pros:** Free tier available, no server setup, instant deployment
**Time:** 15 minutes

```bash
# 1. Go to pythonanywhere.com
# 2. Create free account
# 3. Upload files via web interface (or use Git)
# 4. Create MySQL database in PythonAnywhere
# 5. Configure settings.py with PythonAnywhere credentials
# 6. Run migrations in console
# 7. Reload web app
# 8. Access your site at: yourusername.pythonanywhere.com
```

**Configuration for PythonAnywhere:**

In `shop_management/settings.py`:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'yourusername$shop_management',
        'USER': 'yourusername',
        'PASSWORD': 'your_mysql_password',
        'HOST': 'yourusername.mysql.pythonanywhere-services.com',
        'PORT': '3306',
    }
}

ALLOWED_HOSTS = ['yourusername.pythonanywhere.com', 'localhost']
DEBUG = False  # Turn off debug mode
```

---

### Option 2: AWS EC2 (For Production)

**Pros:** Scalable, reliable, professional hosting
**Time:** 30 minutes
**Cost:** Free tier available (1 year)

```bash
# 1. Create EC2 instance (Ubuntu 20.04)
# 2. SSH into instance
ssh -i your-key.pem ubuntu@your-instance-ip

# 3. Install dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
sudo apt-get install mysql-server mysql-client libmysqlclient-dev

# 4. Clone/upload your Django project
git clone https://github.com/your-repo/shop_management.git
cd shop_management

# 5. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 6. Install Python packages
pip install -r requirements.txt

# 7. Configure MySQL
sudo mysql -u root
# Run database creation commands above

# 8. Update settings for production
# Set DEBUG = False
# Update ALLOWED_HOSTS = ['your-domain.com']
# Change SECRET_KEY to something secure

# 9. Run migrations
python manage.py migrate

# 10. Collect static files
python manage.py collectstatic

# 11. Install Gunicorn & Nginx
pip install gunicorn
sudo apt-get install nginx

# 12. Create systemd service for Gunicorn
sudo nano /etc/systemd/system/shop_django.service

# Add:
[Unit]
Description=Django Shop Management
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/shop_management
ExecStart=/home/ubuntu/shop_management/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 shop_management.wsgi:application

[Install]
WantedBy=multi-user.target

# 13. Start service
sudo systemctl daemon-reload
sudo systemctl start shop_django
sudo systemctl enable shop_django

# 14. Configure Nginx
sudo nano /etc/nginx/sites-available/shop_management

# Add:
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /static/ {
        alias /home/ubuntu/shop_management/staticfiles/;
    }

    location /media/ {
        alias /home/ubuntu/shop_management/media/;
    }
}

# 15. Enable site
sudo ln -s /etc/nginx/sites-available/shop_management /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# 16. Get SSL certificate (free with Let's Encrypt)
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

### Option 3: DigitalOcean (Simple & Affordable)

**Pros:** Simple, affordable ($4/month), good documentation
**Time:** 20 minutes

```bash
# 1. Create Droplet (Ubuntu 20.04)
# 2. SSH into Droplet
# 3. Follow same steps as AWS (Option 2)
# 4. DigitalOcean provides App Platform for one-click deployment
```

---

### Option 4: Heroku (Simplest Deployment)

**Pros:** One-command deployment, automatic scaling
**Time:** 10 minutes
**Cost:** Paid (previous free tier discontinued)

```bash
# 1. Install Heroku CLI
# 2. Create Procfile in project root:
web: gunicorn shop_management.wsgi

# 3. Create runtime.txt:
python-3.10.11

# 4. Deploy
heroku login
heroku create your-app-name
git push heroku main

# 5. Run migrations on Heroku
heroku run python manage.py migrate

# 6. Create superuser
heroku run python manage.py createsuperuser
```

---

## 📱 ACCESS YOUR APPLICATION

After deployment, access your shop management system:

- **Home/Dashboard:** `http://your-domain.com/`
- **Admin Panel:** `http://your-domain.com/admin`
- **POS System:** `http://your-domain.com/sales/pos/`
- **Products:** `http://your-domain.com/inventory/products/`
- **Customers:** `http://your-domain.com/customers/`
- **Reports:** `http://your-domain.com/reports/`

---

## 🔒 SECURITY CHECKLIST

Before going live:

- [ ] Set `DEBUG = False` in settings.py
- [ ] Change `SECRET_KEY` to a random string
- [ ] Set `ALLOWED_HOSTS` to your domain
- [ ] Configure SSL/HTTPS certificate
- [ ] Create superuser with strong password
- [ ] Regular database backups
- [ ] Monitor error logs
- [ ] Set up user authentication properly

---

## 🛠️ MAINTENANCE

### Backup Database:
```bash
mysqldump -u shop_user -p shop_management > backup.sql
```

### Restore Database:
```bash
mysql -u shop_user -p shop_management < backup.sql
```

### Update Django:
```bash
pip install --upgrade django
```

### View Logs (PythonAnywhere):
In Web tab → Error log & Server log

### View Logs (AWS/DigitalOcean):
```bash
sudo journalctl -u shop_django -f
tail -f /var/log/nginx/error.log
```

---

## ❌ TROUBLESHOOTING

### "ModuleNotFoundError: No module named 'django'"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "MySQL connection error"
```bash
# Check MySQL is running
sudo systemctl status mysql

# Verify credentials in settings.py
# Check database exists: SHOW DATABASES;
```

### "Static files not loading"
```bash
python manage.py collectstatic --noinput
```

### "Port 8000 already in use"
```bash
# Use different port
python manage.py runserver 8001
```

### "permission denied" errors
```bash
# Check file permissions
chmod -R 755 shop_management/
# Or run with sudo (not recommended)
```

---

## 📞 SUPPORT RESOURCES

- Django Documentation: https://docs.djangoproject.com/
- PythonAnywhere Help: https://www.pythonanywhere.com/help/
- AWS Documentation: https://docs.aws.amazon.com/
- DigitalOcean Tutorials: https://www.digitalocean.com/community
- Stack Overflow: Search your error message

---

## ✅ YOUR SYSTEM IS NOW LIVE!

**Congratulations!** Your Django Shop Management System is deployed and ready to use.

### Next Steps:
1. Add your products to inventory
2. Register vendors
3. Add customers to database
4. Configure payment methods
5. Train staff on POS system
6. Start generating sales reports

**Happy selling! 🎉**
