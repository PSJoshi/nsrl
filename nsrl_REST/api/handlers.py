from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist

from piston.handler import AnonymousBaseHandler, BaseHandler
from nsrl_api.models import *

class Manufacturer_Handler(BaseHandler):
	allowed_methods = ('GET',)
	model = Manufacturer
	def read(self,request):
		try:
			#print "%s"%request.GET['code']
			search_code = request.GET.get('code',None)
			search_name = request.GET.get('name',None)
			#print search_code,search_name
			if search_code is not None and search_code != '' :
				return self.model.objects.get(code = search_code)
			elif search_name is not None and search_name != '':
				return self.model.objects.filter(name = search_name)
			else:
				return self.model.objects.all()
		#except ObjectDoesNotExist:
		#	return {"error":"not found"}
		except Exception:
			return {"error":"not found"}

class Os_Handler(BaseHandler):
	allowed_methods = ('GET',)
	model = Os
	def read(self,request):
		try:
			#print "%s"%request.GET['system_code']
			search_code = request.GET.get('system_code',None)
			search_name = request.GET.get('system_name',None)
			#print search_code,search_name
			if search_code is not None and search_code != '' :
				return self.model.objects.get(system_code = search_code)
			elif search_name is not None and search_name != '':
				return self.model.objects.filter(name = search_name)
			else:
				return self.model.objects.all()
		#except ObjectDoesNotExist:
		#	return {"error":"not found"}
		except Exception:
			return {"error":"not found"}

class Product_Handler(BaseHandler):
	allowed_methods = ('GET',)
	model = Product
	def read(self,request):
		try:
			#print "%s"%request.GET['product_code']
			search_code = request.GET.get('product_code',None)
			search_name = request.GET.get('product_name',None)
			#print search_code,search_name
			if search_code is not None and search_code != '' :
				return self.model.objects.get(product_code = search_code)
			elif search_name is not None and search_name != '':
				return self.model.objects.filter(name = search_name)
			else:
				return self.model.objects.all()
		#except ObjectDoesNotExist:
		#	return {"error":"not found"}

		except Exception:
			return {"error":"not found"}

class HashFile_Handler_old(BaseHandler):
	allowed_methods = ('GET',)
	model = HashFile

	def read(self,request):
		try:
			#print "%s"%request.GET['product_code']
			search_hash_sha1 = request.GET.get('hash_sha1',None)
			search_hash_md5 = request.GET.get('hash_md5',None)
			search_crc32 = request.GET.get('crc32',None)
			search_filename = request.GET.get('file_name',None)
			search_product_code = request.GET.get('product_code',None)
			search_op_system_code = request.GET.get('op_system_code',None)
			#print search_hash_sha1,search_hash_md5,search_crc32,search_filename,search_product_code,search_op_system_code
			if search_hash_sha1 is not None and search_hash_sha1 != '' :
				return self.model.objects.get(hash_sha1 = search_hash_sha1)
			elif search_hash_md5 is not None and search_hash_md5 != '' :
				return self.model.objects.get(hash_md5 = search_hash_md5)
			elif search_crc32 is not None and search_crc32 != '' :
				return self.model.objects.get(crc32 = search_crc32)
			elif search_filename is not None and search_filename != '':
				return self.model.objects.filter(file_name = search_filename)
			elif search_product_code is not None and search_product_code != '' :
				return self.model.objects.get(product_code = search_product_code)
			elif search_op_system_code is not None and search_op_system_code != '' :
				return self.model.objects.get(op_system_code = search_op_system_code)
			else:
				return self.model.objects.all()[:10]
		#except ObjectDoesNotExist:
		#	return {"error":"not found"}

		except Exception:
			return {"error":"not found"}

class HashFile_Handler(BaseHandler):
	allowed_methods = ('GET',)
	model = HashFile
	#fields = ('file_name','file_size','hash_md5','hash_sha1','crc32','product_code','op_system_code')
	#fields = ('file_name','file_size','hash_md5','hash_sha1','crc32')
	#exclude = ('product_code','os_code','mfg_code')
	def read(self,request):
		try:
			search_hash_sha1 = request.GET.get('hash_sha1',None)
			search_hash_md5 = request.GET.get('hash_md5',None)
			search_crc32 = request.GET.get('crc32',None)
			search_filename = request.GET.get('file_name',None)
			search_product_code = request.GET.get('product_code',None)
			search_op_system_code = request.GET.get('op_system_code',None)
			#print search_hash_sha1,search_hash_md5,search_crc32,search_filename,search_product_code,search_op_system_code
			qset = Q()
			if search_hash_sha1 is not None and search_hash_sha1 != '' :
				qset = qset & Q(hash_sha1__iexact=search_hash_sha1)
			if search_hash_md5 is not None and search_hash_md5 != '' :
				qset = qset & Q(hash_md5__iexact=search_hash_md5)
			if search_crc32 is not None and search_crc32 != '' :
				qset = qset & Q(crc32__icontains=search_crc32)
			if search_filename is not None and search_filename != '':
				qset = qset & Q(file_name__icontains=search_filename)
			if search_product_code is not None and search_product_code != '' :
				qset = qset & Q(product_code__icontains=search_product_code)
			if search_op_system_code is not None and search_op_system_code != '' :
				qset = qset & Q(op_system_code__icontains=search_op_system_code)
			#print qset
			if qset:			
				return self.model.objects.filter(qset).order_by('file_name').distinct()
			else:
				return self.model.objects.all()[:10]
		#except ObjectDoesNotExist:
		#	return {"error":"not found"}

		except Exception:
			return {"error":"not found"}

