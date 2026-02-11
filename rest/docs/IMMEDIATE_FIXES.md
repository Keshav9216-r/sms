# 🚨 IMMEDIATE FIXES REQUIRED
## Critical Security & Stability Issues

**⚠️ DO NOT DEPLOY TO PRODUCTION WITHOUT THESE FIXES ⚠️**

---

## 🔴 CRITICAL FIX #1: Secure Your Settings (15 minutes)

### Step 1: Install python-dotenv (Already in requirements.txt ✅)

### Step 2: Create `.env` file in project root
```bash
# .env
SECRET_KEY=django-insecure-CHANGE-THIS-TO-RANDOM-50-CHARS-xyz123abc456
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com

# Database
DB_NAME=shop_management
DB_USER=shop_user
DB_PASSWORD=your_secure_password_here
DB_HOST=127.0.0.1
DB_PORT=3306
```

### Step 3: Update `shop_management/settings.py`

Replace lines 1-14 with:
```python
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-dev-key-only')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'False') == 'True'

# Only allow specific hosts
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
```

Replace database config (lines 71-82) with:
```python
# Database Configuration - MySQL
DATABASES = {
    'default': {
        'ENGINE': 'mysql.connector.django',
        'NAME': os.getenv('DB_NAME', 'shop_management'),
        'USER': os.getenv('DB_USER', 'shop_user'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST', '127.0.0.1'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'CHARSET': 'utf8mb4',
        'COLLATION': 'utf8mb4_unicode_ci',
    }
}
```

### Step 4: Add `.env` to `.gitignore`
```bash
# Create or update .gitignore
echo ".env" >> .gitignore
echo "*.pyc" >> .gitignore
echo "__pycache__/" >> .gitignore
echo "db.sqlite3" >> .gitignore
echo "/media/" >> .gitignore
echo "/staticfiles/" >> .gitignore
```

---

## 🔴 CRITICAL FIX #2: Fix UserProfile Error (5 minutes)

### Problem
When users log in, they get an error if UserProfile doesn't exist.

### Fix `accounts/views.py`

Replace the dashboard function (lines 23-27):
```python
@login_required
def dashboard(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        # Auto-create profile if it doesn't exist
        user_profile = UserProfile.objects.create(
            user=request.user,
            role='cashier'  # Default role
        )
    
    context = {'user_profile': user_profile}
    return render(request, 'accounts/dashboard.html', context)
```

Replace profile_view function (lines 29-33):
```python
@login_required
def profile_view(request):
    user_profile, created = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={'role': 'cashier'}
    )
    context = {'user_profile': user_profile}
    return render(request, 'accounts/profile.html', context)
```

Replace profile_update function (lines 35-45):
```python
@login_required
def profile_update(request):
    user_profile, created = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={'role': 'cashier'}
    )
    
    if request.method == 'POST':
        user_profile.phone = request.POST.get('phone', '')
        user_profile.address = request.POST.get('address', '')
        user_profile.city = request.POST.get('city', '')
        user_profile.save()
        return redirect('profile')
    
    context = {'user_profile': user_profile}
    return render(request, 'accounts/profile_edit.html', context)
```

---

## 🔴 CRITICAL FIX #3: Complete Admin Panel (10 minutes)

### Fix `accounts/admin.py`
Replace entire file:
```python
from django.contrib import admin
from .models import UserProfile

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'phone', 'city', 'created_at']
    list_filter = ['role', 'city', 'created_at']
    search_fields = ['user__username', 'user__email', 'phone']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'role')
        }),
        ('Contact Details', {
            'fields': ('phone', 'address', 'city')
        }),
        ('Profile Picture', {
            'fields': ('profile_picture',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
```

### Fix `sales/admin.py`
Replace entire file:
```python
from django.contrib import admin
from .models import Sale, SaleItem

class SaleItemInline(admin.TabularInline):
    model = SaleItem
    extra = 0
    readonly_fields = ['product', 'quantity', 'price']
    can_delete = False

@admin.register(Sale)
class SaleAdmin(admin.ModelAdmin):
    list_display = ['id', 'salesperson', 'customer', 'sale_date', 'total_amount', 'payment_method']
    list_filter = ['payment_method', 'sale_date', 'salesperson']
    search_fields = ['customer__customer_name', 'salesperson__username', 'id']
    readonly_fields = ['sale_date', 'total_amount']
    date_hierarchy = 'sale_date'
    inlines = [SaleItemInline]
    
    fieldsets = (
        ('Sale Information', {
            'fields': ('salesperson', 'customer', 'sale_date')
        }),
        ('Payment Details', {
            'fields': ('payment_method', 'total_amount')
        }),
        ('Additional Notes', {
            'fields': ('notes',),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of sales records for audit purposes
        return request.user.is_superuser

@admin.register(SaleItem)
class SaleItemAdmin(admin.ModelAdmin):
    list_display = ['sale', 'product', 'quantity', 'price', 'get_total']
    list_filter = ['sale__sale_date']
    search_fields = ['product__product_name', 'sale__id']
    readonly_fields = ['sale', 'product', 'quantity', 'price']
    
    def get_total(self, obj):
        return obj.quantity * obj.price
    get_total.short_description = 'Total'
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
```

### Fix `inventory/admin.py`
Replace entire file:
```python
from django.contrib import admin
from .models import Product, Category, Inventory

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['category_name', 'created_at']
    search_fields = ['category_name']
    readonly_fields = ['created_at']

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['sku', 'product_name', 'category', 'cost_price', 'selling_price', 'get_profit_margin']
    list_filter = ['category', 'created_at']
    search_fields = ['sku', 'product_name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('sku', 'product_name', 'category')
        }),
        ('Pricing', {
            'fields': ('cost_price', 'selling_price')
        }),
        ('Description', {
            'fields': ('description',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_profit_margin(self, obj):
        if obj.cost_price > 0:
            margin = ((obj.selling_price - obj.cost_price) / obj.cost_price) * 100
            return f"{margin:.2f}%"
        return "N/A"
    get_profit_margin.short_description = 'Profit Margin'

@admin.register(Inventory)
class InventoryAdmin(admin.ModelAdmin):
    list_display = ['product', 'quantity', 'reorder_level', 'get_status', 'last_updated']
    list_filter = ['last_updated']
    search_fields = ['product__product_name', 'product__sku']
    readonly_fields = ['last_updated']
    
    def get_status(self, obj):
        if obj.quantity <= 0:
            return "❌ Out of Stock"
        elif obj.quantity <= obj.reorder_level:
            return "⚠️ Low Stock"
        else:
            return "✅ In Stock"
    get_status.short_description = 'Status'
```

### Fix `customers/admin.py`
Replace entire file:
```python
from django.contrib import admin
from .models import Customer, CustomerContact

class CustomerContactInline(admin.TabularInline):
    model = CustomerContact
    extra = 1

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'phone', 'email', 'customer_type', 'credit_limit', 'city']
    list_filter = ['customer_type', 'city', 'created_at']
    search_fields = ['customer_name', 'phone', 'email']
    readonly_fields = ['created_at', 'updated_at']
    inlines = [CustomerContactInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('customer_name', 'customer_type')
        }),
        ('Contact Details', {
            'fields': ('email', 'phone', 'address', 'city')
        }),
        ('Credit Information', {
            'fields': ('credit_limit',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(CustomerContact)
class CustomerContactAdmin(admin.ModelAdmin):
    list_display = ['contact_name', 'customer', 'contact_phone', 'contact_email']
    search_fields = ['contact_name', 'customer__customer_name', 'contact_phone']
```

### Fix `vendors/admin.py`
Replace entire file:
```python
from django.contrib import admin
from .models import Vendor, VendorContact

class VendorContactInline(admin.TabularInline):
    model = VendorContact
    extra = 1

@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['vendor_name', 'phone', 'email', 'city', 'created_at']
    list_filter = ['city', 'created_at']
    search_fields = ['vendor_name', 'phone', 'email']
    readonly_fields = ['created_at', 'updated_at']
    inlines = [VendorContactInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('vendor_name',)
        }),
        ('Contact Details', {
            'fields': ('email', 'phone', 'address', 'city')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(VendorContact)
class VendorContactAdmin(admin.ModelAdmin):
    list_display = ['contact_name', 'vendor', 'contact_phone', 'contact_email']
    search_fields = ['contact_name', 'vendor__vendor_name', 'contact_phone']
```

### Fix `reports/admin.py`
Create new file:
```python
from django.contrib import admin
from .models import DailyReport

@admin.register(DailyReport)
class DailyReportAdmin(admin.ModelAdmin):
    list_display = ['date', 'total_sales', 'total_quantity_sold', 'number_of_transactions']
    list_filter = ['date']
    search_fields = ['date']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'date'
```

---

## 🔴 CRITICAL FIX #4: Add Stock Validation (10 minutes)

### Fix `sales/views.py`

Replace the create_sale function (lines 21-63) with:
```python
@login_required
def create_sale(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            customer_id = data.get('customer_id')
            items = data.get('items', [])
            payment_method = data.get('payment_method', 'cash')
            
            # Validate items exist
            if not items:
                return JsonResponse({'error': 'No items in cart'}, status=400)
            
            # Validate stock availability BEFORE creating sale
            for item in items:
                product_id = item.get('product_id')
                quantity = int(item.get('quantity', 0))
                
                if not product_id or quantity <= 0:
                    return JsonResponse({'error': 'Invalid item data'}, status=400)
                
                try:
                    product = Product.objects.get(id=product_id)
                    inventory = Inventory.objects.get(product=product)
                    
                    if inventory.quantity < quantity:
                        return JsonResponse({
                            'error': f'Insufficient stock for {product.product_name}. Available: {inventory.quantity}'
                        }, status=400)
                except Product.DoesNotExist:
                    return JsonResponse({'error': f'Product not found'}, status=404)
                except Inventory.DoesNotExist:
                    return JsonResponse({'error': f'Inventory record not found for {product.product_name}'}, status=404)
            
            # Get customer if provided
            customer = None
            if customer_id:
                try:
                    customer = Customer.objects.get(id=customer_id)
                except Customer.DoesNotExist:
                    return JsonResponse({'error': 'Customer not found'}, status=404)
            
            # Create sale
            sale = Sale.objects.create(
                salesperson=request.user,
                customer=customer,
                sale_date=timezone.now(),
                payment_method=payment_method
            )
            
            total_amount = 0
            
            # Create sale items and update inventory
            for item in items:
                product = Product.objects.get(id=item['product_id'])
                quantity = int(item['quantity'])
                price = float(item['price'])
                
                # Create sale item
                SaleItem.objects.create(
                    sale=sale,
                    product=product,
                    quantity=quantity,
                    price=price
                )
                
                # Update inventory
                inventory = Inventory.objects.get(product=product)
                inventory.quantity -= quantity
                inventory.save()
                
                total_amount += quantity * price
            
            # Update sale total
            sale.total_amount = total_amount
            sale.save()
            
            return JsonResponse({
                'success': True,
                'sale_id': sale.id,
                'total': float(total_amount)
            })
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)
```

---

## 🔴 CRITICAL FIX #5: Fix Customer Email Field (2 minutes)

### Fix `customers/models.py`

Change line 11 from:
```python
email = models.EmailField(unique=True)
```

To:
```python
email = models.EmailField(unique=True, blank=True, null=True)
```

Then run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

---

## 🟡 IMPORTANT FIX #6: Add Root URL (2 minutes)

### Fix `shop_management/urls.py`

Replace entire file:
```python
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

urlpatterns = [
    path('', lambda request: redirect('dashboard')),  # Root URL
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('inventory/', include('inventory.urls')),
    path('vendors/', include('vendors.urls')),
    path('customers/', include('customers.urls')),
    path('sales/', include('sales.urls')),
    path('reports/', include('reports.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

---

## ✅ TESTING YOUR FIXES

### 1. Test Environment Variables
```bash
python manage.py shell
>>> from django.conf import settings
>>> print(settings.SECRET_KEY)  # Should show your .env value
>>> print(settings.DEBUG)  # Should be False
>>> print(settings.DATABASES['default']['PASSWORD'])  # Should show your .env value
```

### 2. Test Admin Panel
```bash
python manage.py runserver
```
Visit: http://localhost:8000/admin
- Check all models are visible
- Try adding a product
- Try viewing sales

### 3. Test User Profile
- Login as a user
- Visit dashboard
- Should not crash even if profile doesn't exist

### 4. Test Sale Creation
- Go to POS
- Try to sell more items than in stock
- Should show error message

---

## 📋 VERIFICATION CHECKLIST

After applying all fixes, verify:

- [ ] `.env` file created with all secrets
- [ ] `.env` added to `.gitignore`
- [ ] `settings.py` uses environment variables
- [ ] All admin panels show proper list views
- [ ] UserProfile auto-creates on login
- [ ] Sales validate stock before creating
- [ ] Customer email is optional
- [ ] Root URL redirects to dashboard
- [ ] No hardcoded passwords in code
- [ ] DEBUG is False in production

---

## 🚀 DEPLOYMENT CHECKLIST

Before deploying to production:

- [ ] All immediate fixes applied
- [ ] `.env` file configured for production
- [ ] `DEBUG = False` in production .env
- [ ] `ALLOWED_HOSTS` set to your domain
- [ ] Database credentials secure
- [ ] Static files collected: `python manage.py collectstatic`
- [ ] Migrations applied: `python manage.py migrate`
- [ ] Superuser created: `python manage.py createsuperuser`
- [ ] Test all major features
- [ ] Backup database before going live

---

## ⏱️ TIME ESTIMATE

- Fix #1 (Security): 15 minutes
- Fix #2 (UserProfile): 5 minutes
- Fix #3 (Admin Panel): 10 minutes
- Fix #4 (Stock Validation): 10 minutes
- Fix #5 (Customer Email): 2 minutes
- Fix #6 (Root URL): 2 minutes
- Testing: 15 minutes

**Total Time: ~1 hour**

---

## 🆘 IF SOMETHING BREAKS

### Error: "No module named 'dotenv'"
```bash
pip install python-dotenv
```

### Error: "SECRET_KEY not found"
Make sure `.env` file is in the same directory as `manage.py`

### Error: "Database connection failed"
Check your `.env` database credentials are correct

### Error: "Static files not loading"
```bash
python manage.py collectstatic --noinput
```

### Error: "Migration conflicts"
```bash
python manage.py migrate --fake-initial
```

---

**Apply these fixes in order. Test after each fix. Don't skip any critical fixes!**
