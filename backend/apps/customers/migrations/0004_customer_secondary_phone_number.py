from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0003_remove_customer_total_credit_limit"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="secondary_phone_number",
            field=models.CharField(
                blank=True,
                max_length=15,
                validators=[
                    django.core.validators.RegexValidator(
                        message="Enter valid Nepal mobile number (+977 format)",
                        regex="^\\+?977?9\\d{8,9}$",
                    )
                ],
            ),
        ),
    ]
