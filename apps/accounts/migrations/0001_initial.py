# Generated by Django 3.1.1 on 2020-09-14 08:12

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('username', models.CharField(max_length=255, unique=True)),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('active', models.BooleanField(default=True)),
                ('admin', models.BooleanField(default=False)),
                ('staff', models.BooleanField(default=False)),
                ('confirmed', models.BooleanField(default=False)),
                ('time_stamp', models.DateTimeField(auto_now=True)),
                ('confirmed_date', models.DateTimeField(null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
