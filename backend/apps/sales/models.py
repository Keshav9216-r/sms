from django.db import models
from django.utils import timezone
from apps.inventory.models import Product
from apps.customers.models import Customer, IrregularCustomer

class Sale(models.Model):
    """Sales/Billing Records"""
    
    PAYMENT_METHOD = [
        ('cash', 'Cash'),
        ('card', 'QR'),
        ('credit', 'Credit'),
        ('cheque', 'Cheque'),
        ('momo', 'Mobile Money'),
    ]
    
    PAYMENT_STATUS = [
        ('paid', 'Paid'),
        ('pending', 'Pending'),
        ('partial', 'Partially Paid'),
    ]

    ORDER_STATUS = [
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('returned', 'Returned'),
    ]
    
    sale_number = models.CharField(max_length=50, unique=True)
    receipt_number = models.CharField(max_length=50, unique=True, blank=True)
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, null=True, blank=True, related_name='sales')
    irregular_customer = models.ForeignKey(IrregularCustomer, on_delete=models.SET_NULL, null=True, blank=True, related_name='sales')
    
    cashier = models.ForeignKey('accounts.UserProfile', on_delete=models.SET_NULL, null=True)
    sale_date = models.DateTimeField(auto_now_add=True)
    
    # Amounts
    subtotal = models.DecimalField(max_digits=12, decimal_places=2)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)  # VAT 13% (Nepal)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    
    # Payment
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD, default='cash')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='paid')
    paid_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    order_status = models.CharField(max_length=20, choices=ORDER_STATUS, default='completed')
    
    notes = models.TextField(blank=True)
    is_printed = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'sales'
        ordering = ['-sale_date']
        indexes = [
            models.Index(fields=['sale_number']),
            models.Index(fields=['sale_date']),
        ]
    
    def __str__(self):
        return f"Sale {self.sale_number}"
    
    def save(self, *args, **kwargs):
        # Auto-generate sale number
        if not self.sale_number:
            last_sale = Sale.objects.all().order_by('id').last()
            last_id = last_sale.id if last_sale else 0
            self.sale_number = f"SAL{timezone.now().strftime('%Y%m%d')}{last_id + 1:05d}"

        if not self.receipt_number:
            last_sale = Sale.objects.all().order_by('id').last()
            last_id = last_sale.id if last_sale else 0
            self.receipt_number = f"REC{timezone.now().strftime('%Y%m%d')}{last_id + 1:05d}"
        
        # Calculate due amount
        if self.paid_amount > 0:
            if self.paid_amount >= self.total_amount:
                self.payment_status = 'paid'
            else:
                self.payment_status = 'partial'
        
        super().save(*args, **kwargs)
    
    def due_amount(self):
        return self.total_amount - self.paid_amount


class SaleItem(models.Model):
    """Individual Items in a Sale"""
    
    sale = models.ForeignKey(Sale, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.IntegerField()
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    line_total = models.DecimalField(max_digits=12, decimal_places=2)
    
    class Meta:
        db_table = 'sale_items'
    
    def __str__(self):
        return f"{self.product.product_name} x {self.quantity}"
    
    def get_discount_amount(self):
        """Calculate discount amount for this line"""
        gross = self.unit_price * self.quantity
        return (gross * self.discount_percent) / 100
