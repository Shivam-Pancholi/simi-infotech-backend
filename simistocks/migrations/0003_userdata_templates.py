# Generated by Django 4.0.6 on 2022-08-23 15:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('simistocks', '0002_userdata_whatsapp_phone_no_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='templates',
            field=models.JSONField(default=list),
        ),
    ]