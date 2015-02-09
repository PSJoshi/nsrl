#from celery.schedules import crontab
#import ConfigParser

BROKER_URL = 'amqp://guest:guest@localhost:5672//'
CELERY_IMPORTS = ('tasks', )

CELERY_RESULT_BACKEND = 'amqp'
CELERY_RESULT_PERSISTENT = True
CELERY_TASK_RESULT_EXPIRES = None
#CELERY_TASK_RESULT_EXPIRES = 300
#CELERY_ALWAYS_EAGER = True # useful in debugging
use_proxy = False
use_email = False
timeout_interval = 1
poll_interval = 0.5
proxy_user = None
proxy_password = None
proxy_server = None
proxy_port = '8080'
virustotal_url = 'https://www.virustotal.com/vtapi/v2/file/report'
# to get the key - https://www.virustotal.com/en/documentation/virustotal-community/#build-your-profile
virustotal_key = 
team_cymru_url = 'malware.hash.cymru.com'
use_virustotal = True
use_teamcymru = True

# CELERY_DEFAULT_QUEUE = 'default'
# CELERY_QUEUES = {
#     'default': {
#         'binding_key': 'task.#',
#     },
#     'compute': {
#         'binding_key': 'compute.#',
#     },
#     'result': {
#         'binding_key': 'result.#',
#     },
# }
# CELERY_DEFAULT_EXCHANGE = 'tasks'
# CELERY_DEFAULT_EXCHANGE_TYPE = 'topic'
# CELERY_DEFAULT_ROUTING_KEY = 'task.default'
# CELERY_ROUTES = {
#     'tasks.compute': {
#         'queue': 'compute',
#         'routing_key': 'compute.a_result'
#     },
#     'tasks.handle_result': {
#         'queue': 'result',
#         'routing_key': 'result.handle',
#     },
# }
#
# CELERYBEAT_SCHEDULE = {
#     'every-minute': {
#         'task': 'tasks.add',
#         'schedule': crontab(minute='*/1'),
#         'args': (1,2),
#     },
# }
