# Generated by Django 4.2.4 on 2023-08-28 13:24

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("app_hm10", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="author",
            name="born_date",
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="author",
            name="born_location",
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="author",
            name="fullname",
            field=models.CharField(max_length=255),
        ),
    ]