#!/usr/bin/env python
import fileinput
import os
import sys
import time
import random
try:
    from Crypto.Hash import SHA256 
    HASH_REPS = 1024 #cycles for creating hashes
except:
    raise error("This program requires the Python 2.6 Crypto package")

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

def compare_hash(userHash):
    '''our private hash is stored in a server-side txt file called "keys/generator.hash", we use this to compare incoming hashes'''
    
    try:
        generator = open(PRIVATE_HASH, 'r').read()
    except:
        logger("Failed to open PRIVATE_HASH file: %s."%(PRIVATE_HASH),'e')
        sys.exit(1)

    gen = str(saltedhash_hex(userHash,generator))
    print "chek gen: %s"%(gen)

    if os.path.exists(STORED_HASHES):
        for line in open(STORED_HASHES):
            if gen in line:
                print "0"                
                return 0
            else:
                print "1"
                return 1

    else:
        logger("Failed to open STORED_HASHES file.",'e')
    
pub = str(raw_input("enter public key: "))
ret = compare_hash(pub)
if ret != 1:
    print "MATCH"
