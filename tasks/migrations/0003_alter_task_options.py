# Generated by Django 5.0.1 on 2024-01-21 06:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0002_photo_task_photo_task'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='task',
            options={'ordering': ['-due_date']},
        ),
    ]