# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Remove `managed = False` lines for those models you wish to give write DB access
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin.py sqlcustom [appname]'
# into your database.
from __future__ import unicode_literals

from django.db import models

class Manufacturer(models.Model):
    code = models.CharField(primary_key=True, max_length=50)
    name = models.CharField(max_length=150)
    class Meta:
        managed = False
        db_table = 'manufacturer'


class Os(models.Model):
    system_code = models.CharField(primary_key=True, max_length=50)
    system_name = models.CharField(max_length=150)
    system_version = models.CharField(max_length=50)
    mfg_code = models.ForeignKey(Manufacturer, db_column='mfg_code')
    class Meta:
        managed = False
        db_table = 'os'


class Product(models.Model):
    product_code = models.IntegerField(primary_key=True)
    product_name = models.CharField(max_length=150)
    product_version = models.CharField(max_length=49)
    mfg_code = models.ForeignKey(Manufacturer, db_column='mfg_code')
    os_code = models.ForeignKey(Os, db_column='os_code')
    language = models.CharField(max_length=256)
    application_type = models.CharField(max_length=128)
    class Meta:
        managed = False
        db_table = 'product'

class HashFile(models.Model):
    id = models.IntegerField(primary_key=True)
    file_name = models.CharField(max_length=256)
    file_size = models.BigIntegerField()
    product_code = models.ForeignKey('Product', db_column='product_code')
    op_system_code = models.ForeignKey('Os', db_column='op_system_code')
    special_code = models.CharField(max_length=20)
    hash_sha1 = models.CharField(max_length=40)
    hash_md5 = models.CharField(max_length=40)
    crc32 = models.CharField(max_length=8, blank=True)
    class Meta:
        managed = False
        db_table = 'hash_file'


