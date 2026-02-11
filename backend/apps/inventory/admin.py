from django.contrib import admin
from .models import Product, Category, Inventory, StockAdjustment

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = (
        'sku',
        'product_name',
        'book_name',
        'book_class',
        'book_publication',
        'category',
        'supplier',
        'selling_price',
        'cost_price',
        'is_active',
    )
    list_filter = ('category', 'is_active', 'created_date')
    search_fields = ('product_name', 'book_name', 'book_class', 'book_publication', 'sku', 'barcode', 'supplier')
    ordering = ('product_name',)

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'category_type', 'is_active', 'created_date')
    list_filter = ('category_type', 'is_active')
    search_fields = ('name',)

@admin.register(Inventory)
class InventoryAdmin(admin.ModelAdmin):
    list_display = ('product', 'quantity_in_stock', 'quantity_reserved', 'available_stock', 'low_stock_alert')
    list_filter = ('last_restock_date',)
    search_fields = ('product__product_name',)
    
    def available_stock(self, obj):
        return obj.available_stock
    
    def low_stock_alert(self, obj):
        return obj.low_stock_alert
    low_stock_alert.boolean = True

@admin.register(StockAdjustment)
class StockAdjustmentAdmin(admin.ModelAdmin):
    list_display = ('product', 'adjustment_type', 'quantity_adjusted', 'adjusted_by', 'adjusted_date')
    list_filter = ('adjustment_type', 'adjusted_date')
    search_fields = ('product__product_name',)
    ordering = ('-adjusted_date',)
