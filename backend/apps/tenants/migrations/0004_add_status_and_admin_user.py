# Generated manually for status field and admin_user foreign key

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tenants', '0003_add_access_flags_columns'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='status',
            field=models.CharField(
                choices=[
                    ('active', 'Active'),
                    ('inactive', 'Inactive'),
                    ('suspended', 'Suspended'),
                ],
                default='active',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='tenant',
            name='admin_user',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='managed_tenants',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterField(
            model_name='tenant',
            name='db_user',
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AlterField(
            model_name='tenant',
            name='db_password',
            field=models.CharField(blank=True, max_length=120),
        ),
    ]
