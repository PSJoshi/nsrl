#! /usr/bin/env python

import sys
import os
import argparse
import csv
import logging
import ConfigParser
import string
import MySQLdb


NSRL_FILES = ['NSRLMFG.TXT', 'NSRLOS.TXT', 'NSRLPROD.TXT', 'NSRLFile.txt']

NSRL_OS_FILE = 'NSRLOS.TXT'
NSRL_MFG_FILE = 'NSRLMFG.TXT'
NSRL_PROD_FILE = 'NSRLPROD.TXT'
NSRL_HASH_FILE = 'NSRLFile.txt'


def setup_logging():

    """ set up logging

    """

    logging.basicConfig(level=logging.DEBUG)  # (level=logging.INFO)
    logger = logging.getLogger(__name__)
    #logger.info("Test info message")
    #logger.debug("Test debug message")

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

    app_name = 'NSRL_Hash'
    config_file = ""
    database_host = ""
    database_name = ""
    database_password = ""
    database_type = "mysql"
    database_user = ""
    db_commit = 1  # really commit changes to the database
    #db_uri  = "user/pass@db"
    log_level = logging.ERROR  # only log errors by default
    logger = None
    hash_dir = ""

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

            self.hash_dir = self.__confGet(conf, "hash_files_directory", "hash_dir")
            if not _dir_exists(self.hash_dir):
                self.logger.error("hash file directory specified in the configuration file does not exists."
                                  " Quitting... ")
                sys.exit(1)
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


def connect_MySQL(log_instance, config):

    conn = None
    cursor = None
    try:

        log_instance.info("Connecting to %s MySQL database" % config.app_name)
        conn = MySQLdb.Connection(user=config.database_user, passwd=config.database_password,
                                  host=config.database_host, db=config.database_name)
        cursor = conn.cursor()
    except Exception, e:
        log_instance.error("Error while connecting to MySQL database -%s" % e)
    return conn, cursor


def disconnect_MySQL(log_instance, config, cursor, conn):

    if config.db_commit:
        log_instance.info("Committing the latest entries to database.")
        conn.commit()
    log_instance.info("Disconnecting from %s MySQL database" % config.app_name)
    cursor.close()
    conn.close()
    sys.exit(1)


def update_nsrl_database(log_instance, hash_dir, filename, conn, cursor):
    try:
        row = None
        nsrl_file = os.path.join(os.sep, hash_dir, filename)
        if _file_exists(nsrl_file):
            with open(nsrl_file, "rb") as infile:
                csv_file = csv.reader(infile, delimiter=',')
                # skip header
                header = csv_file.next()

                for row in csv_file:
                    #print row
                    if filename == NSRL_MFG_FILE:
                        try:
                            cursor.callproc('NSRL_MFG_INSERT', row)
                        except Exception, e:
                            log_instance.error("There was an error -%s while updating NSRL manufacturer contents -%s in MySQL database." % (e, row))


                    if filename == NSRL_OS_FILE:
                        try:
                            cursor.callproc('NSRL_OS_INSERT', row)
                        except Exception, e:
                            log_instance.error("There was an error -%s while updating NSRL OS contents -%s in MySQL database." % (e, row))

                    if filename == NSRL_PROD_FILE:
                        try:
                            cursor.callproc('NSRL_PRODUCT_INSERT', row)
                        except Exception, e:
                            log_instance.error("There was an error -%s while updating NSRL product contents -%s in MySQL database." % (e, row))

                    if filename == NSRL_HASH_FILE:
                        try:
                            cursor.callproc('NSRL_HASH_INSERT', row)
                        except Exception, e:
                            log_instance.error("There was an error -%s while updating NSRL hash contents -%s in MySQL database." % (e, row))


        else:
            log_instance.error("%s does not exists in %s directory. Kindly re-check and try again" % (filename, hash_dir))
    except Exception, e:
        log_instance.error("An error -%s is encountered while updating NSRL hash file- %s content -%s in MySQL database." % (e, filename, row))




def main():

    try:
        #setup logging
        conn = cursor = None
        script_logger = setup_logging()
        parser = argparse.ArgumentParser(description='This program inserts NSRL hashes in MySQL database.')
        parser.add_argument('-c', '--config', help='configuration file path', required=True)
        args = parser.parse_args()
        if not args.config:
            script_logger.info("You need to specify configuration file!")
            sys.exit(1)

        # config instance
        config = Config(script_logger, args.config)

        conn, cursor = connect_MySQL(script_logger, config)

        for file_name in NSRL_FILES:
            update_nsrl_database(script_logger,config.hash_dir,file_name, conn,cursor)

        disconnect_MySQL(script_logger, config, cursor, conn)

    except Exception, e:
        if conn:
            conn.rollback()
            conn.close()
        script_logger.error("An error is encounterd while executing NSRL Hash update into MySQL database -%s" % e)
    sys.exit(1)

if __name__ == "__main__":
    main()
