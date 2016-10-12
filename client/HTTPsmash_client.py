#!/usr/bin/python
###################################################################
## DATE: 2010-11-11
## FILE: HTTPsmash_client
## LICENSE: BSD http://www.opensource.org/licenses/bsd-license.php
###################################################################
from __future__ import division
from socket import *
from stat import *
from binascii import *
from base64 import *
from ConfigParser import ConfigParser
import commands
import threading
import os
import sys
import urllib2
import select
import random
import string
import getopt
import time
import logging

ver = sys.version.split(' ')[0].split(".")
major=ver[:1]
minor=ver[1:2]
version="%s.%s"%(major[0],minor[0])
if version in ('2.4','2.3','2.2','2.1','2.0'):
    pyver = "old"
else:
    pyver = "new"

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

#for memory tracking - START
_proc_status = '/proc/%d/status' % os.getpid()
_scale = {'kB': 1024.0, 'mB': 1024.0*1024,
          'KB': 1024.0, 'MB': 1024.0*1024}

def _VmB(VmKey):
    #given a VmKey string, returns a number of bytes
    #get psedo file /proc/<pid>/status
    try:
        t = open(_proc_status)
        v = t.read()
        t.close
    except IOError:
        return 0.0 #Non Linux system?
    #get VmKey line eg: 'VmRSS: 9999 kB\n...'
    i = v.index(VmKey)
    v = v[i:].split(None, 3) #SPLIT on #of whitespace
    if len(v) < 3:
        return 0.0 #invalid format
    #convert Vm value to bytes
    return float(v[1]) * _scale[v[2]]

def memory(since=0.0):
    #return virtual memory in bytes
    return _VmB('VmSize:') - since

def resident(since=0.0):
    #return resident memory in bytes
    return _VmB('VmRSS:') - since

def stacksize(since=0.0):
    #return stack size in bytes
    return _VmB('VmStk:') - since
#for memory tracking - END

class threader(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global url
        global PERTHREAD
        global u
        global suffix
        global rand
        for i in range(PERTHREAD):
            if wait > 0:
                w = round(random.random(),2) + wait
            else:
                w = round(random.random(),1)
            time.sleep(w)
            if suffix == 1 and random > 0:
                str = wordgen()
                url = "%s%s%s"%(u,suffix,str)
            else:
                url = u
            
            logger("OPER|wait: %s|url: %s"%(w,url),'i')
            try:
                start = time.time()
                urllib2.urlopen(url)                
                end = time.time()                
                elapse = end - start
                logger("TIMING|elapse: %s"%(elapse),'i')
            except:
                global ERROR
                ERROR = 1
                logger("Failed to connect to url.",'e')

def randstr(length):
    global url
    twoletters = [c+d for c in string.letters for d in string.letters]
    r = random.random
    n = len(twoletters)
    l2 = length//2
    lst = [None] * l2
    for i in xrange(l2):
        lst[i] = twoletters[int(r() * n)]
        if length & 1:
            lst.append(random.choice(string.letters))

    return "".join(lst)

def FileNotFoundError():
    logger("ERROR: 0021 - Specified wordlist file not found or cannot be read.","i")
    sys.exit(1)

def wordgen():
    var = []
    for v in range(96):
        var.append(randstr(rand))
    return random.choice(var).strip().lower()
            
def looper(loop):
    global suffix
    if random > 0:
        suffix = ""

    conn_persecond = (int(THREADS) * int(PERTHREAD)) / (int(PERTHREAD) * int(wait))
    conn_total = (int(THREADS) * int(PERTHREAD)) * int(repeat)

    logger("---------------------------------------------------",'i')
    logger("Running with the following settings:",'i')
    logger("threads to spawn: %i"%(THREADS),'i') 
    logger("sequential connections per thread: %i"%(PERTHREAD),'i')
    logger("url to strangle: %s"%(u),'i')
    logger("avg wait between connections: %i"%(wait),'i')
    logger("total connections to make: %i"%(conn_total),'i')
    logger("connections per second: %i"%(conn_persecond),'i')
    logger("url suffix append string: %s"%(suffix),'i')
    logger("random string generator char length: %i"%(rand),'i')
    logger("---------------------------------------------------",'i')

    for i in range(loop):
        logger("Running thread loop: %i"%(i),'i')
        retval = init_thread()
        if retval == 1:
            return 1
    return 0        

def init_thread():    
    try:
        backgrounds = []
        for thread in range(THREADS):
            logger("Spawning thread: %s"%(thread),'d')
            background = threader()        
            background.start()
            backgrounds.append(background)
        for background in backgrounds:
            background.join()
        return 0
    
    except:
        return 

def checkfile(file):
    sys.stdout.write("Testing %s access: "% (file))
    if(os.path.exists(file)):
        sys.stdout.write("[exists]")
        try:
            os.ftruncate(file, 0)
            sys.stdout.write("[truncated]\n")
            os.chmod(file,S_IRUSR | S_IWUSR)
            return 0
        except:
            cmd = "echo ''>> %s"%(file)
            retcode, output = commands.getstatusoutput(cmd)
            if retcode != 0:
                sys.stdout.write("[truncate-failed][exiting(1)]\n")
                sys.exit(1)
            else:
                sys.stdout.write("[truncated]\n")
                os.chmod(file,S_IRUSR | S_IWUSR)
                return 0
    else:
        sys.stdout.write("[create-attempt]")
        if(open(file,"a+")):
            sys.stdout.write("[writeable]\n")
            os.chmod(file,S_IRUSR | S_IWUSR)
            return 0
        else:
            sys.stdout.write("[write-failed]\n")
            sys.exit(1)
    

def print_help():
    print '''==================================================
HTTPsmash_client :: per-node client script 
==================================================

REQUIRED SETTINGS

   Flag                   Descrition 
   --logfile=             File to log operations (default ./strangler.log)
   --help                 Print this message

   '''


def decode(data):
    '''simple, decode the data we're processing.'''
    code = unhexlify(urlsafe_b64decode(data))
    logger("OPER.DECODE: %s"%(code),'d')
    return code


def commIO(str):
    '''communication input/output with management server'''
    try:
        var = decode(conn.recv(BUFSIZE))
        if len(var) == 0:
            sys.exit(1)
        logger("OPER.COMM - data var[%s]: [OK]"%(str),'i')
        conn.send("0")
    except:
        logger("OPER.COMM - data var[%s]: [FAIL]"%(str),'i')
        sys.exit(1)
        return 127 #we're having a return value issue if this fails... needs to be addressed
    
    return var


class commVars:
    '''We iterate through each item needed to run a job from the queue'''

    def get(self):
        self.items = {"url":"", "wait":"", "repeat":"", "suffix":"", "rand":"", "THREADS":"", "PERTHREAD":""}
        self.url = str(commIO("url"))
        self.wait = float(commIO("wait"))
        self.repeat = int(commIO("repeat"))
        self.suffix = str(commIO("suffix"))
        self.rand = int(commIO("rand"))
        self.THREADS = int(commIO("client_threads"))
        self.PERTHREAD = int(commIO("client_perthread"))
            
def main():    
    global conn
    global ERROR
    ERROR = 0
    timeout = int(5)    
    conn = socket(AF_INET,SOCK_STREAM)
    conn.settimeout(timeout)

    try:
        conn.connect((ADDR))
        logger("OPER.INIT - job manager connection at %s:%i: [CONNECTED]"%(HOST,PORT),'i')
    except:
        errno, errstr = sys.exc_info()[:2]
        logger("OPER.INIT - job manager connection at %s:%i: [FAILED:%s]"%(HOST,PORT,errstr),'i')
        return 1        

    data = conn.recv(BUFSIZE)
    if decode(data) == "EMPTY":
        logger("OPER.INIT - server job queue is empty. No work to do. Quitting.",'i')
        return 2

    if decode(data) == "INIT":
        logger("OPER.INIT - data stream decode operation: [SUCCESS]",'i')
        
        try:
            pubkey = open("keys/client_key.pub", 'r').read() 
        except:
            logger("OPER.READ - failed to open client_key.pub file.",'e')

        conn.send(pubkey) #send our public key for authentication, if we are valid we continue
        global u
        global wait
        global repeat
        global suffix
        global rand
        global THREADS
        global PERTHREAD
        
        job = commVars()
        job.get()
        
        u = job.url
        wait = job.wait
        repeat = job.repeat
        suffix = job.suffix
        rand = job.rand
        THREADS = job.THREADS
        PERTHREAD = job.PERTHREAD
        retval = looper(repeat)
            
        logger("Retval=%s"%(retval),'d')
        logger("ERROR = %i"%(ERROR),'d')
        if retval == 0 and ERROR == 0:
            try:
                conn.send("job-complete")
                logger("Sending results to manager: [COMPLETE]",'i')
                logger("Final state code: [%s]"%(retval),'d')
                retval = 0
                
            except:
                logger("Sending results to manager: [ERROR]",'i')
                retval = 1                
        else:
            conn.send("job-failed")
            logger("Sending results to manager: [COMPLETE]",'i')
            logger("Final state code: [%s]"%(retval),'d')
            retval = 1
    else:
        conn.send('FAILED')
        logger("Data stream decode operation: [ERROR].",'i')
        retval = 1
        
    conn.close()
    return retval

if __name__ == "__main__":    
    cfg_file = "conf/client.conf"

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
    #global THREADS #num threads to open
    #global u #URL to be tested
    #global PERTHREAD #per connection url hits

    config = ConfigParser()
    config.read([cfg_file])
    headertxt = 'client configuration'
    LOG = str(config.get(headertxt,'LOG'))
    HOST = str(config.get(headertxt,'HOST'))
    PORT = int(config.get(headertxt,'PORT'))
    BUFSIZE = int(config.get(headertxt,'BUFSIZE'))
    ADDR = (HOST,PORT)

    try:
        options, remainder = getopt.getopt(
            sys.argv[1:], '', ['logfile=',
                               'help'])
    except getopt.GetoptError, err:
        print str(err) 
        sys.exit(2)
        
    for opt, arg in options:
        if opt in ('--logfile'):
            LOG = str(arg)
        elif opt in ('--help'):
            print_help()
            sys.exit(2)

    try:
        LOG
        checkfile(LOG)
    except:
        checkfile(LOG)

    #create log instance
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
    #end log creation

    try:
        retval = 0
        while retval == 0:
            retval = main()
            
    except (KeyboardInterrupt, SystemExit):
        logger("DIED: CODE: [%s]"%(retval),'i')
        sys.exit(1)
    else:
        if retval == 1:
            code = "FAIL"
        elif retval == 2:
            code = "WORK COMPLETE"
        elif retval == 0:
            code = "OK"
        logger("FINAL STATE: [%s]"%(code),'i')
        sys.exit(retval)







