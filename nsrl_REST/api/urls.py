from django.conf.urls import patterns, include, url
from api.handlers import *
from piston.resource import Resource

#define resources for the models
resource_manufacturer = Resource(Manufacturer_Handler)
resource_os = Resource(Os_Handler)
resource_product = Resource(Product_Handler)
resource_hashfile = Resource(HashFile_Handler)

urlpatterns = patterns('',
# manufacturer
 url(r'^manufacturer/$',resource_manufacturer),
# url(r'^manufacturer/json$',resource_manufacturer, { 'emitter_format': 'json' }, name='manufacturer-all-json'),
# url(r'^manufacturer/xml$',resource_manufacturer, { 'emitter_format': 'xml' }, name='manufacturer-all-xml'),
# url(r'^manufacturer/json/(?P<code>\w*)/$',resource_manufacturer, { 'emitter_format': 'json' }, name='manufacturer-code-json'),
# url(r'^manufacturer/xml/(?P<code>\w*)/$',resource_manufacturer, { 'emitter_format': 'xml' }, name='manufacturer-code-xml'),
# url(r'^manufacturer/json/(?P<name>\w*)/$',resource_manufacturer, { 'emitter_format': 'json' }, name='manufacturer-name-json'),
# url(r'^manufacturer/xml/(?P<name>\w*)/$',resource_manufacturer, { 'emitter_format': 'xml' }, name='manufacturer-name-xml'),

# Os
 url(r'^os/$',resource_os),
 #url(r'^os/json$',resource_os, { 'emitter_format': 'json' }, name='os-all-json'),
 #url(r'^os/xml$',resource_os, { 'emitter_format': 'xml' }, name='os-all-xml'),
 #url(r'^os/json/(?P<system_code>\w*)/$',resource_os, { 'emitter_format': 'json' }, name='os-json'),
 #url(r'^os/xml/(?P<system_code>\w*)/$',resource_os, { 'emitter_format': 'xml' }, name='os-xml'),

# product
 url(r'^product/$',resource_product),
 #url(r'^product/json$',resource_product, { 'emitter_format': 'json' }, name='product-all-json'),
 #url(r'^product/xml$',resource_product, { 'emitter_format': 'xml' }, name='product-all-xml'),
 #url(r'^product/json/(?P<system_code>\w*)/$',resource_product, { 'emitter_format': 'json' }, name='product-json'),
 #url(r'^product/xml/(?P<system_code>\w*)/$',resource_product, { 'emitter_format': 'xml' }, name='product-xml'),

# hash_file
 url(r'^hash/$',resource_hashfile),
# url(r'^hash/json$',resource_hashfile, { 'emitter_format': 'json' }, name='hash-all-json'),
# url(r'^hash/xml$',resource_hashfile, { 'emitter_format': 'xml' }, name='hash-all-xml'),
# url(r'^hash/json/(?P<id>\d+)/$',resource_hashfile, { 'emitter_format': 'json' }, name='hash-json'),
# url(r'^hash/xml/(?P<id>\d+)/$',resource_hashfile, { 'emitter_format': 'xml' }, name='hash-xml'),

)

