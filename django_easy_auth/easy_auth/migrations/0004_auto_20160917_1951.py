# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2016-09-17 19:51
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('easy_auth', '0003_auto_20160917_1844'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tokenversionforuser',
            name='version',
            field=models.IntegerField(default=1),
        ),
    ]