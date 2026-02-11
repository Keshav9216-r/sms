# Generated manually for superadmin role

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('superadmin', 'Super Administrator'),
                    ('admin', 'Vendor Admin'),
                    ('staff', 'Shop Staff'),
                    ('manager', 'Manager'),
                ],
                default='staff',
                max_length=20,
            ),
        ),
    ]
