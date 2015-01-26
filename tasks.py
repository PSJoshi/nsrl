#! /usr/bin/env python
import subprocess
import time
import datetime
import urllib
import urllib2
import json

import logging
from celery import Celery
from celery.utils.log import get_task_logger

log = get_task_logger(__name__)

celery = Celery('tasks')
celery.config_from_object('celeryconfig')

class Teamcymru():
    """
    This class checks md5/sha1 hash of a file against Team Cymru malware hash registry service:
    Malware hash registry -http://www.team-cymru.org/Services/MHR/
    A big thanks to Team Cymru team for providing this free service.
    """
    __logger = None

    def __init__(self,log_instance=None):
        if log_instance:
            self.__logger = log_instance
        else:
            #self.__logger = logging.getLogger(__name__)
            self.__logger = log

    def check_dns_connectivity(self,ip=None):
        """
            DNS connectivity check
        """
        import socket
        host = None
        try:
            if ip:
                host = socket.gethostbyaddr(ip)
            else:
                host = socket.gethostbyaddr('8.8.8.8')
            return True
        except Exception:
            return False

    def __run_command(self,exec_command, timeout=10, poll_seconds=0.25):
        """
            run the command as a seperate process
        """
        try:
            proc = subprocess.Popen(exec_command, bufsize=0, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.time() + float(timeout)
            while time.time() < deadline and proc.poll() == None:
                time.sleep(float(poll_seconds))
            stdout, stderr = proc.communicate()
            return stdout, stderr
        except Exception, e:
            self.__logger.error("Error while executing the command - %s for Team Cymru malware hash registry check" % exec_command)

    def query_malware_hash_registry(self,team_cymru_url,hash_value, timeout_interval, polling_interval):
        """
            query Team Cymru malware hash registry to check if md5 hash is malware
        """
        try:
            _cmd = "/usr/bin/nslookup -querytype=TXT " + hash_value + '.' + team_cymru_url #'.malware.hash.cymru.com'
            response, error = self.__run_command(_cmd, timeout_interval, polling_interval)
            self.__logger.debug("Team Cymru malware hash registry response - %s" % response)
            if error:
                self.__logger.error("Error while checking Team Cymru malware hash registry - %s and the error is - %s" % (_cmd, error))
            return response, error
        except Exception, e:
            self.__logger.error("Error while checking Team Cymru malware hash registry - %s and the error is - %s" % (_cmd, e))

    def process_team_cymru_response(self, hash_value, team_cymru_url, response):
        """
            Process Team Cymru malware hash response
        """
        try:
            response = response.split('\n')
            for item in response:
                if item.find(hash_value + '.' + team_cymru_url) >= 0:
                    malware_line = item
                    if malware_line.lower().find('nxdomain') >= 0:
                        # no malware present: percent_detection=0,last_detection=current time
                        return False, datetime.datetime.now(), 0
                    else:
                        malware_details = malware_line.strip().split('=')[1]
                        last_updated, percent_detection = malware_details.replace('"', '').strip().split(' ')
                        #print last_updated,percent_detection
                        return True, datetime.datetime.fromtimestamp(long(last_updated)), percent_detection
        except Exception, e:
            self.__logger.error("Error while processing Team Cymru's response - %s and the error is - %s" % (response, e))

class Virustotal():

    __logger = None
    __auth = None
    __proxy = None

    def __init__(self,log_instance=None,use_proxy=None,proxy_user=None, proxy_password=None, proxy_server=None, proxy_port=8080):
        if log_instance:
            self.__logger = log_instance
        else:
            #self.__logger = logging.getLogger(__name__)
            self.__logger = log
        self.use_proxy = use_proxy
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password
        self.proxy_server = proxy_server
        self.proxy_port = proxy_port
        self.proxy_handler = None
        if self.use_proxy:
            __proxy = urllib2.ProxyHandler({'http': 'http://' + proxy_user + ':' + proxy_password + '@' + proxy_server + ':' + proxy_port,
                                    'https': 'http://' + proxy_user + ':' + proxy_password + '@' + proxy_server + ':' + proxy_port})
            __auth = urllib2.HTTPBasicAuthHandler()
            self.proxy_handler = urllib2.build_opener(__proxy, __auth, urllib2.HTTPHandler)

    def check_internet_connectivity(self):
        url = 'http://www.google.com'
        if self.use_proxy:
            urllib2.install_opener(self.proxy_handler)
        try:
            conn = urllib2.urlopen(url)
            response = conn.read()
            #if response.getcode()==200:
            if response:
                return True
            else:
                return False
        except Exception, e:
            self.__logger.error("Error in checking internet connectivity - %s" % str(e).strip())

    def virustotal_filechecker(self,url, api_key,hash_value, filename):
        """
            Check VirusTotal report for the given file's - md5/sha-1 hash
        """
        response = None
        Ismalware = False
        response_dict = None
        report_result = None
        # request using proxy or not
        if self.proxy_handler:
            urllib2.install_opener(self.proxy_handler)
        # POST request parameters
        post_parameters = {"resource": hash_value, "apikey": api_key}
        encoded_data = urllib.urlencode(post_parameters)
        req = urllib2.Request(url, encoded_data)
        try:
            response = urllib2.urlopen(req)
        except Exception, e:
            self.__logger.error("Error while getting VirusTotal report for file - %s - %s." % (filename, str(e).strip()))

        report_result = response.read()
        # http response headers
        self.__logger.debug("Http response headers:\n%s" % (response.info()))
        # http status codes
        self.__logger.debug("Http response code:\n%s" % (response.getcode()))
        # http response
        self.__logger.debug("Http response:\n%s" % (report_result))

        # no response
        if not report_result:
            return None,None

        response_dict = json.loads(report_result)
        if response_dict['response_code'] != 0:
            if response_dict['positives'] != 0:
                Ismalware = True
            else:
                Ismalware = False
        else:
            Ismalware = False
            response_dict = []
            #if response_dict['response_code']==0:
            # print "The file is not a malware as no result could be found in the virustotal database."
            #elif response_dict['response_code']==1:
            # print "The file is a malware and %s virus engines have detected it. Detailed results found in the virustotal database are:" %response_dict['positives']
            # for key,value in json['scans'].items():
            # print key,value['result']
        return Ismalware, response_dict

@celery.task
def add(x,y):
    return x+y


@celery.task
def team_cymru_check(url,hash_value,timeout_interval,poll_interval):
    try:
        teamcymru_instance = Teamcymru()
        #no dns connectivity
        if not teamcymru_instance.check_dns_connectivity():
            return False,None,None
        response,error = teamcymru_instance.query_malware_hash_registry(url,hash_value,timeout_interval,poll_interval)
        return response,error
    except Exception,e:
        log.error("Error while checking Team Cymru malware hash registry for the hash %s - %s" % (hash_value,str(e)))

@celery.task
def virustotal_check(url=None,api_key=None,hash_value=None,filename=None,use_proxy=False,proxy_server=None,proxy_port=8080,proxy_user=None,proxy_passwd=None):

    try:
        virustotal_instance = Virustotal()
        connection_status = virustotal_instance.check_internet_connectivity()
        if not connection_status:
            return None,None
        else:
            return virustotal_instance.virustotal_filechecker(url,api_key,hash_value,filename)
    except Exception,e:
        log.error("Error while checking Virustotal hash registry for the hash %s - %s" % (hash_value,str(e)))