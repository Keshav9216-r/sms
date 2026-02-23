from django.db import models
from django.contrib.auth.models import User


class Tenant(models.Model):
    """Represents a Vendor with isolated database and data"""
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
    ]
    
    name = models.CharField(max_length=150)
    code = models.SlugField(unique=True)
    owner_email = models.EmailField()
    pan_number = models.CharField(max_length=30, blank=True, default='')
    qr_code = models.ImageField(upload_to='qr_codes/', blank=True, null=True)
    
    # Database configuration for this vendor
    # WARNING: db_password is stored as plaintext. In production, use an
    # encrypted field (e.g. django-encrypted-model-fields) or store credentials
    # in a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault) and
    # reference them by a secret ID here instead of the raw password.
    db_name = models.CharField(max_length=120)
    db_user = models.CharField(max_length=120, blank=True)
    db_password = models.CharField(max_length=120, blank=True)
    db_host = models.CharField(max_length=120, default='127.0.0.1')
    db_port = models.CharField(max_length=10, default='5432')
    
    # Feature access control
    access_customers = models.BooleanField(default=True)
    access_vendors = models.BooleanField(default=True)
    access_inventory = models.BooleanField(default=True)
    access_sales = models.BooleanField(default=True)
    access_reports = models.BooleanField(default=True)
    
    # Admin user for this vendor (created by superadmin)
    admin_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_tenants')
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tenants'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.code})"
