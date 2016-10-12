#!/usr/bin/env python2.6
###################################################################
## DATE: 2010-11-11
## FILE: HTTPsmash_server
## LICENSE: BSD http://www.opensource.org/licenses/bsd-license.php
###################################################################
from socket import *
from binascii import *
from base64 import *
from stat import *
from ConfigParser import ConfigParser
from Queue import *
from threading import Thread, Lock
import thread
import logging
import sys
import os
import fileinput
import string
import zlib

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

def DataCompressionFail():
    logger("ERROR: 1001.00 - Data stream compression failed",'e')
    return 0

def ClientConnectionRefuseError():
    logger("ERROR: 1002.00 - Client connection refused.",'e')
    return

def encode(data):
    '''This is basic hexify and base64 encode. We need to switch to m2crypt or keyczar eventually'''
    try:
        code = urlsafe_b64encode(hexlify(data))
        return code
    except:
        logger("ERROR: 1002.00 - Client connection refused.",'e')
        return 1

def print_help():
    print '''==================================================
HTTPsmash_server :: a distributed load testing app
==================================================
Date: 2010-08-26
License: new BSD license
==================================================
Use the following flags to change default behavior
    
   Option                 Description
   --port=                Port to run on
   --buffer=              Buffer size 
   --maxconn=             Maximum connections
   --help                 Print this message
   '''

def response(resp):
    resp = string.rstrip(resp)
    if resp == "0":
        logger("COMM response: %s : [OK]"%(resp),'d')
        return 
    else:
        logger("COMM response: %s : [FAILED]"%(resp),'e')
        sys.exit(1)

def worker():
    while True:
        item = q.get()
        do_work(item) #execute the job
        q.task_done()

def queue_source():
     logger("Opening url file for queue process: %s"%(URLFILE),'d')
     try:
         file = open(URLFILE, "r")         
         return file.readlines()
     except:
         logger("Failed to open url file for queue process.",'e')

def handler(conn,addr):
    global clients #int
    global url #str
    global wait #int
    global repeat #int
    global suffix #str
    global rand #int
    global rand_enable #int 0/1
    global suffix_enable #int 0/1
    global client_threads #int
    global client_perthread #int
    global q
    
    if q.empty() == True:
        logger("Queue: [EMPTY].",'e')
        conn.send(encode("EMPTY")) #tell the client we don't have any work
        sys.exit(1)
    try:
        '''get a job from the queue'''
        logger("Querying Queue.",'i')
        job = q.get()
        logger("Queue job contents: %s"%(job),'d')
        if job[0] == "":
            logger("Queue: job is NULL - perhaps an empty line?",'e')
            return 1
    except:
        logger("Failed to retreive job from queue.",'e')
        return 1
    
        
    '''we read everything as a string because send() doesn't like ints, they will be converted as needed later'''
    try:
        url = str(job[1])
        wait = str(job[2])
        repeat = str(job[3])
        suffix = str(job[4])
        rand = str(job[5])        
        rand_enable = str(job[6])
        suffix_enable = str(job[7]) 
        client_threads = str(job[8])
        client_perthread = str(job[9])
        
    except:
        logger("Failed to parse job variables. Check %s for correct formatting."%(URLFILE),'e')
        return 1

    if rand_enable != "0" and rand_enable != "1":
        logger("rand_enable value configuration failed. Must be 0 or 1 value. Current: %s"%(rand_enable),'e')
        return 1
        
    if suffix_enable != "0" and suffix_enable != "1":
        logger("suffix_enable value configuration failed. Must be 0 or 1 value. Current: %s"%(suffix_enable),'e')
        return 1
    
    logger("CLIENT: %s connected."%(str(addr)),'i')
    conn.send(encode("INIT")) # send data to client
    retval = compare_hash(conn.recv(BUFSIZE)) #compare client's public key to our active store
    if retval == 1:
        logger("Failed to correctly compare client hash. Retval: %s"%(retval),'e')
        sys.exit(1)
    else:
        logger("Hash check: [OK]",'d')

    commvars = [url, wait, repeat, suffix, rand, client_threads, client_perthread]
    for var in commvars:
        v = encode(var)
        conn.send(v) 
        response(str(conn.recv(BUFSIZE)))
             
    '''Final response from client - success/fail'''
    resp = conn.recv(BUFSIZE)
    q.task_done()
    if resp == "job-complete":
        logger("CLIENT: %s,[%s],[url: %s]"%(addr,resp,url),'i')
        conn.close()
        return 0
    else:
        logger("CLIENT: %s,[%s],[url: %s]"%(addr,resp,url),'e')
        conn.close()
        return 1

def connectionPool():
    '''setup connection pool / server process'''
    try:
        serv = socket( AF_INET,SOCK_STREAM)    
        serv.bind((ADDR)) #bind to address
        serv.listen(MAXCON)  #qmax_connections limit
        logger('listening on: %s:%i'%(HOST,PORT),'i')
    except:
        logger("Could not bind to address: %s:%s"%(HOST,PORT),'e')
        sys.exit(1)
        
    global q
    q = Queue()
    logger("Starting Queue",'i')
    try:
        for line in queue_source():
            if not line.startswith('#'):
                d = line.rstrip() #remove endline cruft
                l = d.split(" ") #split on empty space
                
                #parse each job line - this will most likely be database driven in the future
                clients = str(l[0])
                url = str(l[1])
                logger("inserting quantity: %s for url: %s"%(clients,url),'i')
            
                #we insert the URL into the queue $x num times so more than one client can get the job if requested
                #since not all jobs will be able to run with only one client
                if clients != "#":
                    for i in range(int(clients)):
                        logger("inserting url into the queue: %s"%(url),'i')
                        q.put(l)
            
    except:
        logger("Queue initialization: [FAILED]",'e')

    try:
        while 1:
            try:                            
                '''we'll just sit around serving forever unless interrupted.'''
                conn,addr = serv.accept() 
                logger("SERV: [RUNNING]",'i')
                thread.start_new_thread(handler, (conn,addr))

            except (KeyboardInterrupt, SystemExit):
                logger("SERV: [KILLED]",'e')
                serv.close()
                sys.exit(1)

            except:
                logger("SERV: [DEAD]",'e')
                serv.close()
                sys.exit(1)
                
        q.join() #wait for queue to be processed before stopping
        serv.close()
        return 0
                        
    except:
        return 1

    
def main():
    try:
        connectionPool()    
        return 0
    except:
        return 1

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
    URLFILE = str(config.get(headertxt,'URLFILE'))
    ADDR = (HOST,PORT)

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

            

                

