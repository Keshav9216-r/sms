from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0002_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="customer",
            name="total_credit_limit",
        ),
    ]
