#!/usr/bin/env python
###################################################################
## DATE: 2010-11-11
## FILE: queue
## LICENSE: BSD http://www.opensource.org/licenses/bsd-license.php
###################################################################
import os
import time
import urllib2
from Queue import *
from threading import Thread, Lock


def do_work(url):
     start = time.time()
     try:
          urllib2.urlopen(url)                
     except:
          print "FAILED|%s"%(url)
          return
     end = time.time()                
     elapse = str(round((end - start)*1000))+"ms"
     print "TIMING|elapse|%s|%s"%(url,elapse)

def worker():
    while True:
        item = q.get()
        do_work(item)
        q.task_done()

def queue_source():
     global THREADS
     fileIN = open("url_list", "r")
     return fileIN.readlines()     

q = Queue()
for i in range(4):
     t = Thread(target=worker)
     t.setDaemon(True)
     t.start()
    
for url in queue_source():
     url = url.rstrip()
     print "inserting into the queue: %s"%(url)
     q.put(url)

#wait for the queue to be processed before quitting
q.join() 
