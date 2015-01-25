#! /usr/bin/env python
from peewee import *

# sqlite3 database for storing md5 hashes locally and peewee based models
db = SqliteDatabase('hash_md5.db')

class Hash_details(Model):
    hash_md5 = CharField(index=True)
    hash_sha1 = CharField(index=True)
    virustotal_result = BooleanField()
    teamcymru_result = BooleanField()
    class Meta:
        database = db

if not Hash_details.table_exists():
    Hash_details.create_table(True)

#cls_instance=Hash_details.create(hash_md5='aaaa',hash_sha1='bbbb',virustotal_result=True,teamcymru_result=False)
#cls_instance.save()
try:
    #ret=Hash_details.select().where(Hash_details.hash_md5=='aaaa')
    #for item in ret.select():
    #    print item.hash_sha1

    ret=Hash_details.select().where(Hash_details.hash_md5=='aaaa').count()
    print ret

except Hash_details.DoesNotExist:
    print "Exception"
