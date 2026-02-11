from django.db import models

class Category(models.Model):
    """Product Categories"""
    
    CATEGORY_TYPE = [
        ('stationery', 'Stationery'),
        ('books', 'Books'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    category_type = models.CharField(max_length=20, choices=CATEGORY_TYPE)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'categories'
        ordering = ['name']
        verbose_name_plural = 'Categories'
    
    def __str__(self):
        return self.name


class Product(models.Model):
    """Product Master Data"""
    
    sku = models.CharField(max_length=50, unique=True)  # Stock Keeping Unit
    barcode = models.CharField(max_length=100, unique=True, blank=True, null=True)
    product_name = models.CharField(max_length=200)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    description = models.TextField(blank=True)
    supplier = models.CharField(max_length=200, blank=True)
    book_name = models.CharField(max_length=200, blank=True)
    book_class = models.CharField(max_length=50, blank=True)
    book_publication = models.CharField(max_length=200, blank=True)
    image = models.ImageField(upload_to='products/', blank=True, null=True)
    
    cost_price = models.DecimalField(max_digits=10, decimal_places=2)  # Purchase price
    selling_price = models.DecimalField(max_digits=10, decimal_places=2)  # Retail price
    wholesale_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    reorder_level = models.IntegerField(default=10)  # Alert when stock falls below this
    unit = models.CharField(max_length=20, default='piece')
    
    is_active = models.BooleanField(default=True)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'products'
        ordering = ['product_name']
        indexes = [
            models.Index(fields=['sku']),
            models.Index(fields=['barcode']),
        ]
    
    def __str__(self):
        return self.product_name
    
    def profit_margin(self):
        """Calculate profit margin percentage"""
        if self.cost_price > 0:
            return ((self.selling_price - self.cost_price) / self.cost_price) * 100
        return 0
    
    @property
    def current_stock(self):
        """Get current stock quantity"""
        try:
            return self.inventory.quantity_in_stock
        except:
            return 0


class Inventory(models.Model):
    """Stock Management"""
    
    product = models.OneToOneField(Product, on_delete=models.CASCADE, related_name='inventory')
    quantity_in_stock = models.IntegerField(default=0)
    quantity_reserved = models.IntegerField(default=0)  # Reserved for pending orders
    last_restock_date = models.DateField(null=True, blank=True)
    last_counted_date = models.DateField(null=True, blank=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'inventory'
        verbose_name_plural = 'Inventory'
    
    def __str__(self):
        return f"{self.product.product_name} - {self.quantity_in_stock} units"
    
    @property
    def available_stock(self):
        """Available stock = Total - Reserved"""
        return self.quantity_in_stock - self.quantity_reserved
    
    @property
    def low_stock_alert(self):
        """Check if stock is low"""
        return self.quantity_in_stock <= self.product.reorder_level


class StockAdjustment(models.Model):
    """Track stock adjustments"""
    
    ADJUSTMENT_TYPE = [
        ('purchase', 'Purchase'),
        ('sale', 'Sale'),
        ('adjustment', 'Stock Adjustment'),
        ('damage', 'Damage/Loss'),
        ('return', 'Customer Return'),
    ]
    
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='adjustments')
    adjustment_type = models.CharField(max_length=20, choices=ADJUSTMENT_TYPE)
    quantity_adjusted = models.IntegerField()
    notes = models.TextField(blank=True)
    adjusted_by = models.ForeignKey('accounts.UserProfile', on_delete=models.SET_NULL, null=True)
    adjusted_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'stock_adjustments'
        ordering = ['-adjusted_date']
    
    def __str__(self):
        return f"{self.product.product_name} - {self.adjustment_type}"

