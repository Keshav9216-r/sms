from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    """Extended user profile with shop-specific information"""
    
    ROLE_CHOICES = [
        ('superadmin', 'Super Administrator'),  # Platform-wide access
        ('tenant_admin', 'Tenant Admin'),
        ('manager', 'Manager'),
        ('cashier', 'Cashier'),
        ('staff', 'Staff'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='user_profiles',
        db_constraint=False,
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='cashier')
    phone = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=50, blank=True)
    is_active = models.BooleanField(default=True)
    created_date = models.DateTimeField(auto_now_add=True)

    # Per-user module access (vendor admin can toggle these per staff member)
    can_access_inventory = models.BooleanField(default=True)
    can_access_sales     = models.BooleanField(default=True)
    can_access_customers = models.BooleanField(default=True)
    can_access_reports   = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'user_profile'
        ordering = ['-created_date']
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"


class UserEditLog(models.Model):
    """Audit trail: who edited which staff user and what changed."""
    target_user_id  = models.IntegerField()
    target_username = models.CharField(max_length=150)
    edited_by       = models.CharField(max_length=150)
    changes         = models.TextField()
    timestamp       = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_edit_log'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.edited_by} edited {self.target_username} at {self.timestamp}"
