from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0004_add_status_and_admin_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='vendor_person_name',
            field=models.CharField(default='', max_length=150),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='tenant',
            name='pan_number',
            field=models.CharField(default='', max_length=50),
            preserve_default=False,
        ),
    ]
