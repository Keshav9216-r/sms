from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0004_add_status_and_admin_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenant',
            name='pan_number',
            field=models.CharField(blank=True, max_length=30),
        ),
    ]
