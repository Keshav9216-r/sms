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
    
    class Meta:
        db_table = 'user_profile'
        ordering = ['-created_date']
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"
