from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0005_add_vendor_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='vendor_phone',
            field=models.CharField(default='', max_length=20),
            preserve_default=False,
        ),
    ]
