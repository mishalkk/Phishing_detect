# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2021-01-20 06:49
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('App', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='register',
            name='dep',
        ),
        migrations.RemoveField(
            model_name='register',
            name='uid',
        ),
        migrations.RemoveField(
            model_name='register',
            name='utype',
        ),
    ]