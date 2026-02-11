from django.contrib import admin
from .models import Sale, SaleItem

@admin.register(Sale)
class SaleAdmin(admin.ModelAdmin):
    list_display = ('sale_number', 'receipt_number', 'customer', 'cashier', 'total_amount', 'payment_method', 'payment_status', 'sale_date')
    list_filter = ('payment_method', 'payment_status', 'sale_date')
    search_fields = ('sale_number', 'customer__customer_name')
    ordering = ('-sale_date',)

@admin.register(SaleItem)
class SaleItemAdmin(admin.ModelAdmin):
    list_display = ('sale', 'product', 'quantity', 'unit_price', 'line_total')
    search_fields = ('sale__sale_number', 'product__product_name')
