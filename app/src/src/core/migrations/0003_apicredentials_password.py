# Generated by Django 2.2.13 on 2021-08-09 16:37

from django.db import migrations, models
import src.core.models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_apicredentials'),
    ]

    operations = [
        migrations.AddField(
            model_name='apicredentials',
            name='password',
            field=models.CharField(default=src.core.models.password_default, max_length=8),
        ),
    ]
