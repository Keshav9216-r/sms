from django.db import models
from django.core.validators import RegexValidator

class Customer(models.Model):
    """Customer Database - Mobile number as primary identifier"""
    
    phone_regex = RegexValidator(
        regex=r'^\+?977?9\d{8,9}$',  # Nepal phone format
        message="Enter valid Nepal mobile number (+977 format)",
    )
    
    # Nepal format: +977XXXXXXXXXX or 9XXXXXXXXX
    phone_number = models.CharField(
        max_length=15,
        unique=True,
        validators=[phone_regex],
        db_index=True
    )
    secondary_phone_number = models.CharField(
        max_length=15,
        blank=True,
        validators=[phone_regex],
    )
    
    customer_name = models.CharField(max_length=100)
    email = models.EmailField(blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=50, blank=True)
    notes = models.TextField(blank=True)
    
    # Credit Management
    current_credit = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    loyalty_points = models.IntegerField(default=0)
    
    registration_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'customers'
        ordering = ['customer_name']
        indexes = [
            models.Index(fields=['phone_number']),
        ]
    
    def __str__(self):
        return f"{self.customer_name} ({self.phone_number})"
    



class IrregularCustomer(models.Model):
    """Irregular customer (not stored in regular customer list)."""

    customer_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
    created_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'irregular_customers'
        ordering = ['-created_date']

    def __str__(self):
        return self.customer_name


class CreditTransaction(models.Model):
    """Credit Transaction History"""
    
    TRANSACTION_TYPE = [
        ('purchase', 'Purchase'),
        ('payment', 'Payment Received'),
        ('adjustment', 'Credit Adjustment'),
        ('refund', 'Refund'),
    ]
    
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='credit_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    balance_after = models.DecimalField(max_digits=10, decimal_places=2)  # Running balance
    
    description = models.TextField(blank=True)
    related_sale = models.ForeignKey('sales.Sale', on_delete=models.SET_NULL, null=True, blank=True)
    
    created_by = models.ForeignKey('accounts.UserProfile', on_delete=models.SET_NULL, null=True)
    transaction_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'credit_transactions'
        ordering = ['-transaction_date']
    
    def __str__(self):
        return f"{self.customer.customer_name} - {self.transaction_type}"
