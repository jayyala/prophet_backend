# Generated by Django 4.2.6 on 2024-09-29 02:35

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField()),
                ('username', models.CharField(max_length=255)),
                ('source_ip', models.GenericIPAddressField()),
                ('event_type', models.CharField(max_length=50)),
                ('file_size_mb', models.IntegerField(blank=True, null=True)),
                ('application', models.CharField(max_length=50)),
                ('success', models.BooleanField()),
                ('is_suspicious', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='SuspiciousIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='SuspiciousIPRange',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cidr', models.CharField(max_length=18, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='SuspiciousUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(max_length=255, unique=True)),
            ],
        ),
    ]
