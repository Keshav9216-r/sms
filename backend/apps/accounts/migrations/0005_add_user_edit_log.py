from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0004_add_user_module_access"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserEditLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("target_user_id",  models.IntegerField()),
                ("target_username", models.CharField(max_length=150)),
                ("edited_by",       models.CharField(max_length=150)),
                ("changes",         models.TextField()),
                ("timestamp",       models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "user_edit_log",
                "ordering": ["-timestamp"],
            },
        ),
    ]
