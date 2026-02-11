from django.contrib import admin
from .models import Customer, CreditTransaction

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('customer_name', 'phone_number', 'secondary_phone_number', 'email', 'current_credit')
    list_filter = ('registration_date',)
    search_fields = ('customer_name', 'phone_number', 'email')
    ordering = ('customer_name',)

@admin.register(CreditTransaction)
class CreditTransactionAdmin(admin.ModelAdmin):
    list_display = ('customer', 'transaction_type', 'amount', 'balance_after', 'transaction_date')
    list_filter = ('transaction_type', 'transaction_date')
    search_fields = ('customer__customer_name',)
    ordering = ('-transaction_date',)
