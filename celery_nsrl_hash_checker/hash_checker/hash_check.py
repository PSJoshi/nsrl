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
from peewee import *
from tasks import team_cymru_check, virustotal_check

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

def setup_local_hashdb(log_instance,config_instance):
    try:
        # sqlite3 database for storing md5 hashes locally and peewee based models
        if config_instance.hash_algorithm.lower()=='md5':
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
        log_instance.error("Error while generating local md5/sha-1 hash database - %s" %e.message)

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
    log_level = logging.ERROR  # only log errors by default
    logger = None
    hash_dir = ""
    suspicious_hash_dir = ''
    md5_program = ''
    sha1_program = ''
    use_email_option = False
    email_user = ''
    email_password = ''
    email_server = ''
    email_port = ''
    hash_registry_url = ''
    hash_algorithm = 'md5'
    use_virustotal = False
    use_teamcymru = False

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
                self.logger.error("The directory for storing suspicious files hashes as specified in configuration file does not exists.\n"
                                  " Quitting... ")
                sys.exit(1)

            self.md5_program = self.__confGet(conf, "hash_directory", "md5_program") or self.md5_program
            if self.md5_program:
                if not _file_exists(self.md5_program):
                    self.logger.error("No executable file -%s for computation of md5 hashes is found in the path as specified in the configuration file."
                                  " Quitting... " % self.md5_program)
                    sys.exit(1)

            self.sha1_program = self.__confGet(conf, "hash_directory", "sha1_program") or self.sha1_program
            if self.md5_program:
                if not _file_exists(self.md5_program):
                    self.logger.error("No executable file -%s for computation of sha1 hashes is found in the path as specified in the configuration file."
                                  " Quitting... " % self.sha1_program)
                    sys.exit(1)

            self.hash_algorithm = self.__confGet(conf, "hash_directory", "hash_algorithm") or self.hash_algorithm
            
            self.hash_registry_url = self.__confGet(conf, "hash_registry", "url") or self.hash_registry_url

            self.use_email_option = self.__confGet(conf, "general", "use_email")
            if self.use_email_option.lower()=='yes':
                self.use_email_option = True
            else:
                self.use_email_option = False

            # e-mail
            self.email_user = self.__confGet(conf, "e-mail", "user") or None
            self.email_password = self.__confGet(conf, "e-mail", "password") or None
            self.email_server = self.__confGet(conf, "e-mail", "server") or None
            self.email_port = self.__confGet(conf, "e-mail", "port") or None

            self.use_teamcymru = self.__confGet(conf, "general", "use_teamcymru") or self.use_teamcymru
            if self.use_teamcymru.lower()=='yes':
                self.use_teamcymru = True
            else:
                self.use_teamcymru = False

            self.use_virustotal = self.__confGet(conf, "general", "use_virustotal") or self.use_virustotal
            if self.use_virustotal.lower()=='yes':
                self.use_virustotal = True
            else:
                self.use_virustotal = False


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
        log_instance.error("Error while doing hash registry check for md5 %s -%s"%(md5,e.message))

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


def generate_hashes(log_instance,hash_program,hash_dir,hash_file_path):
    """
        Generate md5/sha1 hashes for directory
    """
    try:
        hash_command = '%s -rel %s >> %s' % (hash_program, hash_dir, hash_file_path)
        log_instance.info("Computing hash using command  - %s" % hash_command)
        stdout, stderror = run_command(log_instance, hash_command)
        if not stderror.strip():
            log_instance.info("Hash program has successfully computed md5/sha-1 hashes of the directory %s in -%s"%(hash_dir,hash_file_path))
        else:
            log_instance.info("Some errors were encountered while computing md5/sha-1 hashes for the directory %s -%s"%(hash_dir,stderror.strip()))
    except Exception,e:
        log_instance.error('Error while generating md5/sha1 hashes for directories %s-%s' %(hash_dir,e.message))

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
                "Unable to send an E-mail that lists suspicious files as detected by Team Cymru malware/VirusTotal service. - %s" % e.message)


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
        #if previous hash file exists, delete it
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
        script_logger.info("Now, checking the hashes against NSRL Hash registry for finding non-trusted files.")
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
        script_logger.info("NSRL Hash registry checks are now over.")
        script_logger.info("Now, checking the hashes against Team Cymru / Virustotal services.")

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
                script_logger.info("Submitting hash %s to Team Cymru malware hash registry through celery queue." % item[0])
                team_cymru_check.delay(item[0])
                script_logger.info("Hash %s is now submitted to Team Cymru malware hash registry. The results will be updated soon." % item[0])

            if config.use_virustotal:
                script_logger.info("Submitting hash %s to VirusTotal malware check service through celery queue." % item[0])
                virustotal_check.delay(item[0], item[2]) # hash, filename
                script_logger.info("Hash %s is now submitted to VirusTotal malware check service. The results will be updated soon." % item[0])

        script_logger.info("md5/sha-1 hash checking against various hash databases like NSRL database, Team Cymru Malware"
                           " Hash registry and VirusTotal malware database is now finished successfully.")
        sys.exit(1)

    except Exception, e:
        script_logger.error("An error is encountered while checking file hashes against Hash databases -%s" % e.message)

if __name__ == "__main__":
    main()