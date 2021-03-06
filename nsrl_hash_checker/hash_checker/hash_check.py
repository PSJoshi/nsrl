#! /usr/bin/env python

import sys
import os
import argparse
import csv
import logging
import ConfigParser
import string
import time
import subprocess
import hashlib
import json
import requests
import urlparse
from team_cymru_malware_check import Teamcymru
from virustotal_malware_check import Virustotal
from peewee import *

# Constants
input_hash_file = 'input_hash.txt'

def _file_exists(file_name):

    if os.path.isfile(file_name):
        return True
    else:
        return False


def _dir_exists(dir_name):

    if os.path.isdir(dir_name):
        return True
    else:
        return False


def is_file_old(log_instance, file_name, delete_days_interval=60):
    import datetime
    try:
        modified_time = os.path.getmtime(file_name)
        creation_time = os.path.getctime(file_name)
        #creation_time = time.ctime(os.path.getctime(file_name))
        file_age = datetime.datetime.now() - datetime.datetime.fromtimestamp(creation_time)
        if file_age.days>=delete_days_interval:
            os.remove(file_name)
    except Exception,e:
        log_instance.error("Error while deleting old local hash database file - %s" % file_name)

def setup_local_hashdb(log_instance,config_instance):
    try:
        # sqlite3 database for storing md5 hashes locally and peewee based models
        if config_instance.hash_algorithm.lower()=='md5':
            # delete local database hash file if too old
            is_file_old(log_instance,'hash_md5.db')

            db = SqliteDatabase('hash_md5.db')
            class Hash_details(Model):
                hash_md5 = CharField(index=True)
                virustotal_result = BooleanField()
                teamcymru_result = BooleanField()
                class Meta:
                    database = db
        else:
            db = SqliteDatabase('hash_sha1.db')
            class Hash_details(Model):
                hash_sha1 = CharField(index=True)
                virustotal_result = BooleanField()
                teamcymru_result = BooleanField()
                class Meta:
                    database = db
        if not Hash_details.table_exists():
            Hash_details.create_table(True)
        return Hash_details
    except Exception,e:
        log_instance.error("Error while generating local md5/sha-1 hash database - %s" %e)

def setup_logging():

    """ set up logging

    """

    logging.basicConfig(level=logging.DEBUG)  # (level=logging.INFO)
    logger = logging.getLogger(__name__)

    # set up file handler
    handler = logging.FileHandler('nsrl_hash.log')
    handler.setLevel(logging.DEBUG)

    # logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)
    # logger.info("Test info message for file handler")
    return logger


class Config:

    app_name = 'NSRL_Hash_Check'
    config_file = ""
    database_host = ""
    database_name = ""
    database_password = ""
    database_type = "mysql"
    database_user = ""
    db_commit = 0
    log_level = logging.ERROR  # only log errors by default
    logger = None
    hash_dir = ""
    suspicious_hash_dir = ''
    md5_program = ''
    sha1_program = ''
    use_proxy_option = False
    use_email_option = False
    timeout = 1
    poll_interval = 0.5
    proxy_user = ''
    proxy_password = ''
    proxy_server = ''
    proxy_port = ''
    email_user = ''
    email_password = ''
    email_server = ''
    email_port = ''
    virustotal_url = ''
    virustotal_key = ''
    use_virustotal = False
    team_cymru_url = ''
    use_teamcymru = False
    hash_registry_url = ''
    hash_algorithm = 'md5'

    def __init__(self, log_instance=None, config_file=None):
        self.logger = log_instance
        self.__readConfig(config_file)

    def __readConfig(self, configfile):
        """ read configuration parameters"""

        try:
            conf = ConfigParser.ConfigParser()
            conf.read(configfile)
            self.config_file = configfile
            # Log level
            self.log_level = self.__confGet(conf, "logging", "log_level") or self.log_level
            self.logger.setLevel(int(self.log_level))
            self.app_name = self.__confGet(conf, "app", "name") or self.app_name

            #Database parameters
            #self.db_uri = self.__confGet(conf, "database", "url") or self.db_uri
            self.database_type = self.__confGet(conf, "database", "db_type") or self.database_type
            self.database_name = self.__confGet(conf, "database", "db_name") or self.database_name
            self.database_host = self.__confGet(conf, "database", "host") or self.database_host
            self.database_user = self.__confGet(conf, "database", "user") or self.database_user
            self.database_password = self.__confGet(conf, "database", "passwd") or self.database_password

            if self.__confGet(conf, "database", "commit"):
                if string.upper(self.__confGet(conf, "database", "commit"))[0] == 'Y':
                    self.db_commit = 1

            self.hash_dir = self.__confGet(conf, "hash_directory", "hash_dir")
            if self.hash_dir.find(',')>0:
                hash_dirs = self.hash_dir.split(',')
                for h_dir in hash_dirs:
                    if not _dir_exists(h_dir):
                        self.logger.error("Some of the directories for hash generation in configuration file do not exist."
                                  " Kindly re-check and try again. \n\n Quitting... ")
                        sys.exit(1)
                self.hash_dir = hash_dirs
            else:
                if not _dir_exists(self.hash_dir):
                    self.logger.error("Some of the directories for hash generation in configuration file do not exist."
                                      " Kindly re-check and try again. \n\n Quitting... ")
                    sys.exit(1)
            self.suspicious_hash_dir  = self.__confGet(conf, "hash_directory", "suspicious_hash_dir")
            if not _dir_exists(self.suspicious_hash_dir):
                self.logger.error("In the configuration file, directory specified for storing suspicious files hashes does not exists.\n"
                                  " Quitting... ")
                sys.exit(1)

            self.md5_program = self.__confGet(conf, "hash_directory", "md5_program") or self.md5_program
            if self.md5_program:
                if not _file_exists(self.md5_program):
                    self.logger.error("No md5 hash program file -%s for computation of file hashes is found in the path as specified in the configuration file."
                                  " Quitting... " % self.md5_program)
                    sys.exit(1)

            self.sha1_program = self.__confGet(conf, "hash_directory", "sha1_program") or self.sha1_program
            if self.sha1_program:
                if not _file_exists(self.sha1_program):
                    self.logger.error("No sha-1 hash program file -%s for computation of file hashes is found in the path as specified in the configuration file."
                                  " Quitting... " % self.sha1_program)
                    sys.exit(1)

            self.hash_algorithm = self.__confGet(conf, "hash_directory", "hash_algorithm") or self.hash_algorithm
            
            self.hash_registry_url = self.__confGet(conf, "hash_registry", "url") or self.hash_registry_url
            # if not self.hash_registry_url:
            #     self.logger.error("It seem that you have forgotten to specify md5/sha-1 hash registry URL."
            #                       "Kindly enter it in the configuration file and then, try again.\n"
            #                       " Quitting... ")
            #     sys.exit(1)

            self.use_proxy_option = self.__confGet(conf, "general", "use_proxy")
            if self.use_proxy_option.lower()=='no':
                self.use_proxy_option = False
            else:
                self.use_proxy_option = True

            self.use_email_option = self.__confGet(conf, "general", "use_email")
            if self.use_email_option.lower()=='no':
                self.use_email_option = False
            else:
                self.use_email_option = True

            self.timeout = self.__confGet(conf, "general", "timeout_interval")
            self.poll_interval = self.__confGet(conf, "general", "poll_interval")
            self.team_cymru_url = self.__confGet(conf, "general", "team_cymru_url")
            self.use_teamcymru = self.__confGet(conf, "general", "use_teamcymru")

            if self.use_teamcymru.lower()=='no':
                self.use_teamcymru = False
            else:
                self.use_teamcymru = True

            self.virustotal_url = self.__confGet(conf, "general", "virustotal_url") or self.virustotal_url
            self.virustotal_key = self.__confGet(conf, "general", "virustotal_key") or self.virustotal_key
            self.use_virustotal = self.__confGet(conf, "general", "use_virustotal") or self.use_virustotal

            if self.use_virustotal.lower()=='no':
                self.use_virustotal = False
            else:
                self.use_virustotal = True

            if not(self.use_virustotal or self.use_teamcymru):
                self.logger.error("Kindly choose at least one of source either Virustotal or Team Cymru for checking suspicious md5/sha-1 hashes"
                                  "and then try again."
                                )
                sys.exit(1)
            if self.use_virustotal:
                if not (self.virustotal_url and self.virustotal_key):
                    self.logger.error("Kindly make sure that you have specified both virustotal url and the virustotal key in configuration file.")
                    sys.exit(1)
            if self.use_teamcymru:
                if not (self.team_cymru_url):
                    self.logger.error("Kindly make sure that you have specified Team cymru url in the configuration file.")
                    sys.exit(1)
            # proxy
            self.proxy_user = self.__confGet(conf, "proxy", "user") or None
            self.proxy_password = self.__confGet(conf, "proxy", "password") or None
            self.proxy_server = self.__confGet(conf, "proxy", "server") or None
            self.proxy_port = self.__confGet(conf, "proxy", "port") or 8080
            # e-mail
            self.email_user = self.__confGet(conf, "e-mail", "user") or None
            self.email_password = self.__confGet(conf, "e-mail", "password") or None
            self.email_server = self.__confGet(conf, "e-mail", "server") or None
            self.email_port = self.__confGet(conf, "e-mail", "port") or None

        except Exception, e:
            self.logger.error("Error while reading configuration file -%s " % e)

    def __confGetSection(self, conf, section):
        """returns the value of all the configuration options in one section or None if not set"""
        try:
            options = {}
            for i in conf.items(section):
                options[i[0]] = i[1]
            return options
        except ConfigParser.Error:
            return None  # ignore missing values

    def __confGet(self, conf, section, option):
        """returns the value of the configuration option or None if not set"""
        try:
            return conf.get(section, option)
        except ConfigParser.Error:
            return None  # ignore missing values

def run_command(log_instance,exec_command, timeout=5, poll_seconds=0.25):
    """ run exec_command as a seperate process"""
    try:
        proc = subprocess.Popen(exec_command, bufsize=0, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + float(timeout)
        while time.time() < deadline and proc.poll() is None:
            time.sleep(float(poll_seconds))
            stdout, stderr = proc.communicate()
        return stdout, stderr
    except Exception, e:
        log_instance.error("Error while executing the command - %s" % exec_command)

def hash_registry_check(log_instance,hash_registry_url,md5,f_name):
    """
        checking md5 hash against hash registry
    """
    try:
        check_url = hash_registry_url+'%s&file_name=%s'%(md5,f_name)
        #checking if url is valid or not.
        parsed_url = urlparse.urlparse(check_url)
        if parsed_url:
            r=requests.get(check_url)
            return json.dumps(r.json())
    except Exception,e:
        log_instance.error("Error while doing hash registry check for md5 %s -%s"%(md5))

def generate_hashes(log_instance,hash_program,hash_dir,hash_file_path):
    """
        Generate md5/sha1 hashes for directory
    """
    try:
        hash_command = '%s -rel %s >> %s' % (hash_program, hash_dir, hash_file_path)
        log_instance.info("Computing md5 hash using command  - %s" % hash_command)
        stdout, stderror = run_command(log_instance, hash_command)
        if not stderror.strip():
            log_instance.info("md5 program has successfully computed md5 hashes of the directory %s in -%s"%(hash_dir,hash_file_path))
        else:
            log_instance.info("Some errors were encountered while computing md5 hashes for the directory %s -%s"%(hash_dir,stderror.strip()))
    except Exception,e:
        log_instance.error('Error while generating md5/sha1 hashes for directories %s-%s' %(hash_dir,e))

def compute_hash_sha1(f_path):
    """
     Compute SHA-1 of file
    """

    sha1 = hashlib.sha1()
    f = open(f_path,'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()


def mail_to_user(log_instance, email_user, email_password, email_server, message):
    import smtplib, base64
    from email.mime.multipart import MIMEMultipart
    # Import the email modules that we'll need
    from email.mime.text import MIMEText

    from_mail = email_user + '@' + email_server
    to_mail = email_user + '@' + email_server
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Detection of malware files on your PC'
    msg['From'] = email_user + '@' + email_server
    msg['To'] = email_user + '@' + email_server
    msg_part = MIMEText(message, 'plain')
    msg.attach(msg_part)
    try:
        so = smtplib.SMTP(email_server)
        so.docmd("AUTH LOGIN", base64.b64encode(email_user))
        so.docmd(base64.b64encode(email_password), "")
        #so.login(email_user,email_password)
        try:
            so.sendmail(from_mail, to_mail, msg.as_string())
        except Exception, e:
            log_instance.error("Suspicious files: %s" % message)
            log_instance.error(
                    "There is an error in sending e-mail about suspicious files as detected by Team Cymru malware/VirusTotal services %s" % e)
        finally:
            so.close()
    except Exception, e:
        log_instance.error(
                "Unable to send an E-mail that lists suspicious files as detected by Team Cymru malware/VirusTotal service. - %s" % e)


def main():

    try:
        #setup logging
        script_logger = setup_logging()
        script_logger.info("Checking md5 hashes against NSRL database...")
        parser = argparse.ArgumentParser(description=("This program compares md5/sha-1 hashes of directorie(s)"
                                                      "against NSRL hash registry and checks suspicious hashes"
                                                      "against Team Cymru and Virustotal malware hash registry"))
        parser.add_argument('-c', '--config', help='configuration file path', required=True)
        args = parser.parse_args()
        if not args.config:
            script_logger.info("Kindly specify the configuration file first!")
            sys.exit(1)

        # config instance
        script_logger.info("Reading configuration file...")
        config = Config(script_logger, args.config)
        script_logger.info("Configuration file is read successfully.")
        #setup local hash database - this is to ensure minimum look ups for Team Cymru/Virustotal services
        script_logger.info("Setting up local hash database..")
        hash_details = setup_local_hashdb(script_logger,config)
        script_logger.info("Local hash database is now setup successfully.")

        # Running md5deep or sha1deep command to compute hashes
        script_logger.info("Now running md5deep/sha1deep program for computation of hashes for directory -%s..." % config.hash_dir)

        hash_file_path = os.path.join(os.path.sep,config.suspicious_hash_dir,input_hash_file)
        #if previous hash file exists, delete it (md5deep/sha1deep program will regenerate it anyway).
        if _file_exists(hash_file_path):
            os.remove(hash_file_path)

        if config.hash_algorithm.lower()=="md5":
            if type(config.hash_dir) is list:
                for h_dir in config.hash_dir:
                    generate_hashes(script_logger,config.md5_program,h_dir,hash_file_path)
            else:
                generate_hashes(script_logger,config.md5_program, config.hash_dir, hash_file_path)
        else:
            if type(config.hash_dir) is list:
                for h_dir in config.hash_dir:
                    generate_hashes(script_logger,config.sha1_program,h_dir,hash_file_path)
            else:
                generate_hashes(script_logger,config.sha1_program, config.hash_dir, hash_file_path)

        script_logger.info("Computation of md5/sha1 hashes for given directories is now complete.")

        script_logger.info("Now, checking the hashes against VirusTotal/Team Cymru malware service.")

        suspicious_hashes = []
        if config.hash_registry_url:

            # read the hash file
            with open(hash_file_path, "rb") as infile:
                csv_file = csv.reader(infile, delimiter=',')
                for row in csv_file:
                    #print row[0].split(' ')[0]
                    md5 = row[0].split(' ')[0].strip()
                    full_path = row[0].split(' ')[2].strip()
                    path, f_name = os.path.split(full_path)
                    script_logger.info("Checking md5 hash against hash registry -%s" %md5)
                    result = hash_registry_check(script_logger,config.hash_registry_url, md5, f_name)
                    script_logger.info("No %s entry found in hash database - %s" %(md5, f_name))
                    if result:
                        suspicious_hashes.append(row)
            no_lines = sum (1 for line in open(hash_file_path))
            script_logger.info("There were %s files (out of %s) that are not having md5 hashes in NSRL database."%(len(suspicious_hashes),no_lines))
        else:
            with open(hash_file_path, "rb") as infile:
                csv_file = csv.reader(infile, delimiter=',')
                for row in csv_file:
                    suspicious_hashes.append(row)

        # Team cymru malware check
        # create instance of Team Cymru class
        cls_teamcymru = Teamcymru(script_logger)
        # create instance of Virustotal class
        cls_virustotal = Virustotal(script_logger)
        proxy_handler = None
        virustotal_result = False
        teamcymru_result = False
        # Virustotal check
        if config.use_proxy_option:
            proxy_handler = cls_virustotal._setup_proxy(config.proxy_server,config.proxy_port,config.proxy_user,config.proxy_password)
        #check internet connectivity
        if not cls_virustotal.check_internet_connectivity(config.use_proxy_option,config.proxy_user,config.proxy_password,config.proxy_server,config.proxy_port):
            script_logger.error("An error is encountered while checking internet connection."
            "Kindly make sure that internet connection is ON and then try again. Quitting...")
            sys.exit(1)

        # check DNS connectivity
        if not cls_teamcymru.check_dns_connectivity():
           script_logger.error("The program is unable to make DNS queries to Team Cymru server."
                               "Kindly make sure that DNS service is operating correctly on the PC."
                               "Quitting...")
           sys.exit(1)
        malicious_hashes = []
        for hash_entry in suspicious_hashes:
            item = hash_entry[0].split(' ')
            if config.hash_algorithm.lower()=='md5':
                #check if md5 exists in local database - ie. whether it was scanned earlier
                cnt = hash_details.select().where(hash_details.hash_md5==item[0]).count()
                if cnt>=1:
                    #hash does exists in local database. So, do not query TeamCymru database/Virustotal database...
                    continue
            else:
                #check if sha1 exists in local database - ie. whether it was scanned earlier
                cnt = hash_details.select().where(hash_details.hash_sha1==item[0]).count()
                if cnt>=1:
                    #hash does exists in local database. So, do not query TeamCymru database/Virustotal database...
                    continue

            # query malware hash registry
            if config.use_teamcymru:
                script_logger.info("Queying Team Cymru malware hash registry..")
                response,error = cls_teamcymru.query_malware_hash_registry(config.team_cymru_url,item[0],config.timeout,config.poll_interval)
                if error:
                    script_logger.error("An error is encountered while querying Team Cymru malware hash registry.")
                    teamcymru_result = False
                else:
                    script_logger.info("Processing response from Team Cymru malware hash registry...")
                    teamcymru_result,last_seen,percent_detection = cls_teamcymru.process_team_cymru_response(item[0],config.team_cymru_url,response)
                    script_logger.info("Team Cymru response - Ismalware -%s, last seen - %s and percent detection %s" %(teamcymru_result,last_seen,percent_detection))

            if config.use_virustotal:
                script_logger.info("Querying VirusTotal service...")
                virustotal_result,detailed_response = cls_virustotal.virustotal_filechecker(config.virustotal_url,config.virustotal_key,item[2],item[0],proxy_handler)
                script_logger.info("Virustotal response - Ismalware - %s and detailed response - %s" %(virustotal_result,detailed_response))

            if config.hash_algorithm.lower()=='md5':
                hash_details.create(hash_md5=item[0],teamcymru_result=teamcymru_result,virustotal_result=virustotal_result)
            else:
                hash_details.create(hash_sha1=item[0],teamcymru_result=teamcymru_result,virustotal_result=virustotal_result)

            # if any virus/malware is detected
            if teamcymru_result or virustotal_result:
                malicious_hashes.append([item[0],item[2],teamcymru_result,virustotal_result])

        if malicious_hashes:
            script_logger.info("The details of virus/malware threats that were found in the directory -%s are given in 'malicious_files.txt'." %config.hash_dir)
            hash_files = '\n'.join(malicious_hashes)
            e_message = ("""The following files have been makred as suspicious by Team Cymru/Virustotal malware services.\n
                Please make sure to check these files using latest anti-virus/anti-malware softwares.\n %s""" % hash_files)
            if config.use_email_option:
                mail_to_user(script_logger,config.email_user,config.email_password,config.email_server,config.email_port,e_message)
            else:
                #write to file
                f = open('malicious_files.txt','w')
                f.write(e_message)
                f.close()
        else:
            script_logger.info("No virus/malware threats were found in the directory -%s" %config.hash_dir)

        script_logger.info("md5/sha-1 hash checking against NSRL database, Team Cymru Malware Hash registry and VirusTotal database is now finished successfully.")
        sys.exit(1)

    except Exception, e:
        script_logger.error("An error is encountered while checking file hash against NSRL Hash database -%s" % str(e))

if __name__ == "__main__":
    main()