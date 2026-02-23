from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    """Extended user profile with shop-specific information"""

    ROLE_CHOICES = [
        ('superadmin', 'Super Administrator'),
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

    # Per-staff module access permissions
    can_access_inventory = models.BooleanField(default=True)
    can_access_sales = models.BooleanField(default=True)
    can_access_customers = models.BooleanField(default=True)
    can_access_reports = models.BooleanField(default=False)

    class Meta:
        db_table = 'user_profile'
        ordering = ['-created_date']

    def __str__(self):
        return f"{self.user.username} ({self.role})"

    @property
    def is_staff_level(self):
        """True for roles that have restricted permissions (staff/cashier)."""
        return self.role in ('staff', 'cashier')


class ChangeLog(models.Model):
    """Audit trail of create/update/delete actions made by staff users."""

    ACTION_CHOICES = [
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
    ]

    username = models.CharField(max_length=150)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=60)
    record_id = models.CharField(max_length=100)
    description = models.TextField()
    before_data = models.TextField(blank=True, default='')
    after_data = models.TextField(blank=True, default='')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'change_log'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username} {self.action} {self.model_name} @ {self.timestamp:%Y-%m-%d %H:%M}"
