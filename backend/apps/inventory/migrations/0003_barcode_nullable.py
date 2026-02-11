from django.db import migrations, models


def normalize_empty_barcodes(apps, schema_editor):
    Product = apps.get_model('inventory', 'Product')
    db_alias = schema_editor.connection.alias
    Product.objects.using(db_alias).filter(barcode='').update(barcode=None)


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0002_product_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='barcode',
            field=models.CharField(blank=True, max_length=100, null=True, unique=True),
        ),
        migrations.RunPython(normalize_empty_barcodes, migrations.RunPython.noop),
    ]
