#!/usr/bin/env python
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

def create_randhash():
    for i in range(256):
        str0 = time.time()
        str0 += random.random()        
        
    for i in range(256):
        str1 = time.time()
        str1 += random.random()

    return saltedhash_hex(str(str0),str(str1))


def store_private(userID):
    '''when adding a new client we need to create a server-side-stored unique hash that is compare to their public-key-hash for authentication'''
    '''our private hash is stored in a server-side txt file called "keys/generator.hash", we use this to generate new hashes and compare incomign hashes'''

    try:
        generator = open(PRIVATE_HASH, 'r').read()
    except:
        logger("Failed to open hash file.",'e')
        sys.exit(1)

    userprivate_hash = saltedhash_hex(userID,generator)
    f = open(STORED_HASHES, 'a+')
    f.write(userprivate_hash+"\n")
    f.close()


print "\nThis creates a public key to be used by each unique client that connects to the managerd process. This public key must be stored on the client system in the same directory as the stranglerc app in a file called 'client_key.pub'. The private key for this public key is automatically stored in the keys/stored_keys.hash file on the managerd server.\n\n"
pubhash = create_randhash()
print "PUBLIC-KEY: %s"%(pubhash)
store_private(pubhash)
