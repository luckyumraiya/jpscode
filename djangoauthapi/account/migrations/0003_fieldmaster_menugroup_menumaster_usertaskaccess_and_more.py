# Generated by Django 4.0.3 on 2023-01-02 12:37

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_remove_menumaster_groupname_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='FieldMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fieldmas', models.CharField(max_length=50)),
                ('placeholdermsg', models.CharField(max_length=100)),
                ('errormsg', models.CharField(max_length=100)),
                ('inactivefield', models.BooleanField()),
                ('notefield', models.CharField(max_length=50)),
                ('lastupdateuserfield', models.CharField(max_length=50)),
                ('lastupdatedatefield', models.DateField(auto_now=True)),
                ('lastupdatetimefield', models.TimeField(auto_now=True)),
                ('lastupdatetaskfield', models.CharField(max_length=50)),
                ('lastupdateipfield', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='MenuGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('grpname', models.CharField(max_length=20)),
                ('sequence', models.CharField(max_length=1)),
                ('inactive', models.BooleanField()),
                ('note', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='MenuMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('menuname', models.CharField(max_length=20)),
                ('taskname', models.CharField(max_length=20)),
                ('groupname', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.menugroup')),
            ],
        ),
        migrations.CreateModel(
            name='UserTaskAccess',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('inactivetaskacc', models.BooleanField()),
                ('notetaskacc', models.CharField(max_length=50)),
                ('viewaccess', models.BooleanField()),
                ('addaccess', models.BooleanField()),
                ('editaccess', models.BooleanField()),
                ('deleteaccess', models.BooleanField()),
                ('inactiveaccess', models.BooleanField()),
                ('lastupdateuseracc', models.CharField(max_length=50)),
                ('lastupdatedateacc', models.DateField(auto_now=True)),
                ('lastupdatetimeacc', models.TimeField(auto_now=True)),
                ('lastupdatetaskacc', models.CharField(max_length=50)),
                ('lastupdateipacc', models.CharField(max_length=20)),
                ('taskacc', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.menumaster')),
                ('useracc', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TaskMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=100)),
                ('pyname', models.CharField(max_length=30)),
                ('inactivetask', models.BooleanField()),
                ('notetask', models.CharField(max_length=50)),
                ('lastupdatedate', models.DateField(auto_now=True)),
                ('lastupdatetime', models.TimeField(auto_now=True)),
                ('lastupdatetask', models.CharField(max_length=50)),
                ('lastupdateip', models.CharField(max_length=20)),
                ('lastupdateuser', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('task', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.menumaster')),
            ],
        ),
        migrations.CreateModel(
            name='TaskFieldMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('restricted', models.BooleanField()),
                ('inactivetaskfield', models.BooleanField()),
                ('notetaskfield', models.CharField(max_length=50)),
                ('lastupdateusertaskfield', models.CharField(max_length=50)),
                ('lastupdatedatetaskfield', models.DateField(auto_now=True)),
                ('lastupdatetimetaskfield', models.TimeField(auto_now=True)),
                ('lastupdatetasktaskfield', models.CharField(max_length=50)),
                ('lastupdateiptaskfield', models.CharField(max_length=20)),
                ('fieldtaskfield', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.fieldmaster')),
                ('tasktaskfield', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.menumaster')),
                ('usertaskfield', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
