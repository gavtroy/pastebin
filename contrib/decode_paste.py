#!/usr/bin/env python3

import base64, hashlib, sys, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
    print('usage: python decode_paste.py <url>')
    sys.exit(-1)

url_parts = list(sys.argv[1].rpartition('/'))
url_parts[0] = url_parts[0].removesuffix('/raw') + '/raw'
url = ''.join(url_parts)
payload = urllib.request.urlopen(url).read()
try:
    password = url.split('#')[1].split('.')[0].encode()
except:
    print(payload.decode())
    sys.exit()

if chr(password[1]) == ':':
    sys.stderr.write('Password: ')
    password += input().encode()

payload = base64.b64decode(payload)
salt, ciphertext = payload[2:14], payload[14:]
kdf = PBKDF2HMAC(hashes.SHA256(), 44, salt, 100000).derive(password)
key, iv = kdf[:32], kdf[32:]
try :
    print(AESGCM(key).decrypt(iv, ciphertext, None).decode())
except:
    print("Bad decryption")
    sys.exit(-2)
