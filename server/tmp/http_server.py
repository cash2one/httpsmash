#!/usr/bin/env python
from socket import *
from binascii import *
from base64 import *
from stat import *
from ConfigParser import ConfigParser
from bottle import abort, request, route, run, PasteServer
from pymongo import Connection
import bottle as web
import thread
import logging
import sys
import os
import fileinput
import string
import zlib
import json

try:
    from Crypto.Hash import SHA256 
    HASH_REPS = 1024 #cycles for creating hashes
except:
    raise error("This program requires the Python 2.6 Crypto package")

ver = sys.version.split(' ')[0].split(".")
major=ver[:1]
minor=ver[1:2]
version="%s.%s"%(major[0],minor[0])
if version in ('2.4','2.3','2.2','2.1','2.0'):
    pyver = "old"
else:
    pyver = "new"


########### HTTP ROUTES
connection = Connection('localhost', 27017)
db = connection.foo

'''index'''
@route('/')
@route('/index.html')
def index():
    return "<a href='/'>Nothing to see here.</a>"

'''debug controller to show post/get/cookies'''
@web.route('/do/:cmd') #url is: http://host:port/do/show
def cmd(cmd):
    if cmd=="show":
        yield "<li>cookies : %s</li>"% str(web.request.COOKIES)
        yield "<li>get : %s</li>"%     str(web.request.GET)
        yield "<li>post : %s</li>"%    str(web.request.POST)
    else:
        web.redirect("/")

'''insert a job -- needs to be moved to an admin only / auth only method'''
@route('/documents', method='PUT')
def put_document():

    '''incoming data format as follows please: 
    {
    "_id": "%int",
    "org_name": "%str",
    "job_name": "%str, 
    "job_url": "%str", 
    "max_hits_per_second": "%int",
    "concurrent_clients_max": "%int",
    "total_runtime_seconds": "%int",
    "connection_wait_interval": "%int", 
    "query_string_conditional": "%str", 
    "query_string_conditional_enable": "0/1", 
    "query_string_random_length": "%int", 
    "query_string_random_enable": "0/1",
    "datetime_run": "%DT",
    "datetime_created": "%DT",
    "datetime_updated": "%DT"
    }
    '''

    data = request.body.readline()
    if not data:
        abort(400, 'No data received')

    entity = json.loads(data)
    if not entity.has_key('_id'):
        abort(400, 'No _id specified')

    try:
        db['documents'].save(entity)
    except ValidationError as ve:
        abort(400, str(ve))

'''get most recent job from db'''
@route('/documents/:id', method='GET')
def get_document(id):
    logger("getJob page called. id: %s, key: %s"%(id,key),'i')

    if not key:
        abort(404, 'No authentication key provided.') 
        
    retval = compare_hash(key)
    if retval == 1:
        logger("Failed to correctly compare client hash. Retval: %s"%(retval),'e')
        sys.exit(1)

    logger("Hash check: [OK]",'d')       
    entity = db['documents'].find_one({'_id':id})
    if not entity:
        abort(404, 'No document with id %s' % id)
    return entity

############


def encode(data):
    '''This is basic hexify and base64 encode. We need to switch to m2crypt or keyczar eventually'''
    try:
        code = urlsafe_b64encode(hexlify(data))
        return code
    except:
        raise DataCompressionFail()

def print_help():
    print '''==================================================
HTTPsmash_server :: a distributed load testing app
==================================================
Use the following flags to change default behavior
    
   Option                 Description
   --port=                Port to run on
   --buffer=              Buffer size 
   --maxconn=             Maximum connections
   --help                 Print this message
   '''
def logger(detail,level):
    if(level == "d"):
        log.debug("%s"% (detail))
    elif(level == "i"):
        log.info("%s"% (detail))
    elif(level == "w"):
        log.warn("%s"% (detail))
    elif(level == "e"):
        log.error("%s"% (detail))
    elif(level == "c"):
        log.critical("%s"% (detail))

'''START encryption functions'''
PRIVATE_HASH = 'keys/generator.hash'
STORED_HASHES = 'keys/stored.hash'

def __saltedhash(string, salt):
    sha256 = SHA256.new()
    sha256.update(string)
    sha256.update(salt)
    for x in xrange(HASH_REPS): 
        sha256.update(sha256.digest())
        if x % 10: sha256.update(salt)
    return sha256

def saltedhash_hex(string, salt):
    """returns the hash in hex format"""
    return __saltedhash(string, salt).hexdigest()

def compare_hash(resp):
    '''our private hash is stored in a server-side txt file called "keys/generator.hash", we use this to compare incoming hashes'''
    userHash = string.rstrip(resp)
    logger("Received client hash: %s"%(userHash),'d')
    try:
        generator = open(PRIVATE_HASH, 'r').read()
    except:
        logger("Failed to open PRIVATE_HASH file: %s."%(PRIVATE_HASH),'e')
        sys.exit(1)
        
    gen = str(saltedhash_hex(userHash,generator))
    logger("Generated comparison key: %s"%(gen),'d')
    if os.path.exists(STORED_HASHES):
        for line in open(STORED_HASHES):
            logger("Current line comparison key: %s"%(line),'d')
            if gen in line:
                return 0
            else:
                return 1            
    else:
        logger("Failed to open STORED_HASHES file.",'e')
        return 1
'''END encryption functions'''


def main():
    web.debug(DEV)
    web.run(server=PasteServer, host=HOST, port=PORT)

if __name__ == "__main__":
    cfg_file = "conf/server.conf"

    '''test if cfg_file exists, else exit'''
    sys.stdout.write("Testing %s config access: "% (cfg_file))
    if(os.path.exists(cfg_file)):
        sys.stdout.write("[exists]")
        if(os.access(cfg_file, os.R_OK)):
            sys.stdout.write("[readable]\n")
        else:
            sys.stdout.write("[read-failed][exiting(1)]\n")
            sys.exit(1)
    else:
        sys.stdout.write("[config file does not exist][exiting(1)]\n")
        sys.exit(1)

    '''initilize config settings'''
    config = ConfigParser()
    config.read([cfg_file])
    headertxt = 'server configuration'
    LOG = config.get(headertxt,'LOG')
    HOST = config.get(headertxt,'HOST') 
    PORT = int(config.get(headertxt,'PORT'))
    MAXCON = int(config.get(headertxt,'MAXCON'))
    BUFSIZE = int(config.get(headertxt,'BUFSIZE'))
    DEV = str(config.get(headertxt,'DEV'))
    ADDR = (HOST,PORT)    

    global URL
    global WAIT
    global REPEAT
    global CONDITIONAL
    global RAND
    global RAND_ENABLE
    global CONDITIONAL_ENABLE
    global WORDLIST

    '''start logging'''
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s|%(levelname)s|%(message)s")
    c = logging.StreamHandler(sys.stdout)
    c.setLevel(logging.INFO)
    c.setFormatter(formatter)
    f = logging.FileHandler(LOG)
    f.setLevel(logging.DEBUG)
    f.setFormatter(formatter)    
    log.addHandler(c)
    log.addHandler(f)

    logger("running with the following server settings:",'i')
    logger("LOG: %s"%(LOG),'i')
    logger("HOST: %s"%(HOST),'i')
    logger("PORT: %s"%(PORT),'i')
    logger("MAXCON: %s"%(MAXCON),'i')
    logger("BUFSIZE: %s"%(BUFSIZE),'i')

    try:
        main()

    except (KeyboardInterrupt, SystemExit):
        retval = 1
        logger("INTERRUPT: RETVAL: [%s]"%(retval),'e')
        logger("Closing serv.process",'e')
        conn.close()
        sys.exit(1)
