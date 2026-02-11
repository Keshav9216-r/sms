from django.db import migrations, models
import django.db.models.deletion


def normalize_roles(apps, schema_editor):
    UserProfile = apps.get_model('accounts', 'UserProfile')
    UserProfile.objects.filter(role='admin').update(role='tenant_admin')
    UserProfile.objects.filter(role='staff').update(role='cashier')


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0004_add_status_and_admin_user'),
        ('accounts', '0002_alter_userprofile_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='tenant',
            field=models.ForeignKey(
                blank=True,
                db_constraint=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='user_profiles',
                to='tenants.tenant',
            ),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('superadmin', 'Super Administrator'),
                    ('tenant_admin', 'Tenant Admin'),
                    ('manager', 'Manager'),
                    ('cashier', 'Cashier'),
                    ('staff', 'Staff'),
                ],
                default='cashier',
                max_length=20,
            ),
        ),
        migrations.RunPython(normalize_roles, noop_reverse),
    ]
