from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_changelog_staff_permissions'),
    ]

    operations = [
        migrations.AddField(
            model_name='changelog',
            name='before_data',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='changelog',
            name='after_data',
            field=models.TextField(blank=True, default=''),
        ),
    ]
