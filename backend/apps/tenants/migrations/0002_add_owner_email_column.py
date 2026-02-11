from django.db import migrations


def _column_exists(schema_editor, table_name, column_name):
    connection = schema_editor.connection
    try:
        description = connection.introspection.get_table_description(connection.cursor(), table_name)
    except Exception:
        return False
    return any(col.name == column_name for col in description)


def add_owner_email_column(apps, schema_editor):
    if _column_exists(schema_editor, "tenants", "owner_email"):
        return
    if schema_editor.connection.vendor == "sqlite":
        schema_editor.execute(
            "ALTER TABLE tenants ADD COLUMN owner_email varchar(254) NOT NULL DEFAULT ''"
        )
    elif schema_editor.connection.vendor in {"postgresql", "mysql"}:
        schema_editor.execute(
            "ALTER TABLE tenants ADD COLUMN owner_email varchar(254) NOT NULL DEFAULT ''"
        )
    else:
        schema_editor.execute(
            "ALTER TABLE tenants ADD COLUMN owner_email varchar(254) NOT NULL DEFAULT ''"
        )


class Migration(migrations.Migration):
    dependencies = [
        ("tenants", "0001_initial"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[migrations.RunPython(add_owner_email_column, migrations.RunPython.noop)],
            state_operations=[],
        )
    ]
