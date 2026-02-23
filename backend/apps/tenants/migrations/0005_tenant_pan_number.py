# The pan_number column already exists in the database (added outside of Django
# migrations). This migration only updates the model state so that Django's ORM
# is aware of the field.  The SeparateDatabaseAndState pattern is used so that
# no DDL is executed against the existing schema.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenants', '0004_add_status_and_admin_user'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # Update model state only — column already exists in DB.
            state_operations=[
                migrations.AddField(
                    model_name='tenant',
                    name='pan_number',
                    field=models.CharField(blank=True, default='', max_length=30),
                ),
            ],
            # No database operations needed; the column is already present.
            database_operations=[],
        ),
    ]
