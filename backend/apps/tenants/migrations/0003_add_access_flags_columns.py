from django.db import migrations


def add_access_flag_columns(apps, schema_editor):
    columns = [
        "access_customers",
        "access_vendors",
        "access_inventory",
        "access_sales",
        "access_reports",
    ]
    for column in columns:
        try:
            schema_editor.execute(
                f"ALTER TABLE tenants ADD COLUMN {column} bool NOT NULL DEFAULT 1"
            )
        except Exception:
            # Column likely already exists.
            pass


class Migration(migrations.Migration):
    dependencies = [
        ("tenants", "0002_add_owner_email_column"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[migrations.RunPython(add_access_flag_columns, migrations.RunPython.noop)],
            state_operations=[],
        )
    ]
