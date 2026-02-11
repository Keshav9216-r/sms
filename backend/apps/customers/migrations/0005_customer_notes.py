from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0004_customer_secondary_phone_number"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="notes",
            field=models.TextField(blank=True),
        ),
    ]
