from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0006_product_supplier"),
    ]

    operations = [
        migrations.AddField(
            model_name="product",
            name="book_class",
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name="product",
            name="book_name",
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name="product",
            name="book_publication",
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
