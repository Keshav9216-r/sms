from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Tenant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=150)),
                ('code', models.SlugField(unique=True)),
                ('owner_email', models.EmailField(max_length=254)),
                ('db_name', models.CharField(max_length=120)),
                ('db_user', models.CharField(max_length=120)),
                ('db_password', models.CharField(max_length=120)),
                ('db_host', models.CharField(default='127.0.0.1', max_length=120)),
                ('db_port', models.CharField(default='5432', max_length=10)),
                ('access_customers', models.BooleanField(default=True)),
                ('access_vendors', models.BooleanField(default=True)),
                ('access_inventory', models.BooleanField(default=True)),
                ('access_sales', models.BooleanField(default=True)),
                ('access_reports', models.BooleanField(default=True)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'tenants',
                'ordering': ['name'],
            },
        ),
    ]
