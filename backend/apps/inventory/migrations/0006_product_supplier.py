from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0005_barcode_unique_with_suffix"),
    ]

    operations = [
        migrations.AddField(
            model_name="product",
            name="supplier",
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
