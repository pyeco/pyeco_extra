#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import struct
import traceback
import hashlib
import time
try: from cStringIO import StringIO
except: from StringIO import StringIO

def pack_int(i):
	return struct.pack(">i", i)

def pack_short(i):
	return struct.pack(">h", i)

def pack_byte(i):
	return struct.pack(">b", i)

def pack_long(i):
	return struct.pack(">q", i)

def pack_unsigned_int(i):
	return struct.pack(">I", i)

def pack_unsigned_short(i):
	return struct.pack(">H", i)

def pack_unsigned_byte(i):
	return struct.pack(">B", i)

def pack_unsigned_long(i):
	return struct.pack(">Q", i)

def unpack_int(s):
	return struct.unpack(">i", s)[0]

def unpack_short(s):
	return struct.unpack(">h", s)[0]

def unpack_byte(s):
	return struct.unpack(">b", s)[0]

def unpack_long(i):
	return struct.unpack(">q", i)[0]

def unpack_unsigned_int(s):
	return struct.unpack(">I", s)[0]

def unpack_unsigned_short(s):
	return struct.unpack(">H", s)[0]

def unpack_unsigned_byte(s):
	return struct.unpack(">B", s)[0]

def unpack_unsigned_long(s):
	return struct.unpack(">Q", s)[0]

def io_unpack_int(io):
	return struct.unpack(">i", io.read(4))[0]

def io_unpack_short(io):
	return struct.unpack(">h", io.read(2))[0]

def io_unpack_byte(io):
	return struct.unpack(">b", io.read(1))[0]

def io_unpack_long(io):
	return struct.unpack(">q", io.read(8))[0]

def io_unpack_unsigned_int(io):
	return struct.unpack(">I", io.read(4))[0]

def io_unpack_unsigned_short(io):
	return struct.unpack(">H", io.read(2))[0]

def io_unpack_unsigned_byte(io):
	return struct.unpack(">B", io.read(1))[0]

def io_unpack_unsigned_long(io):
	return struct.unpack(">Q", io.read(8))[0]

def int_to_bytes(i, length=0x100):
	hex_code = hex(i)
	if hex_code.startswith("0x"):
		hex_code = hex_code[2:]
	if hex_code.endswith("L"):
		hex_code = hex_code[:-1]
	return "0"*(length-len(hex_code))+hex_code
	#return hex_code+"0"*(length-len(hex_code))

def bytes_to_int(bytes):
	return int(bytes, 16)

def get_prime():
	#openssl genrsa -out private.key 2048
	#openssl rsa -in private.key -out public.key -pubout
	#openssl rsa -in private.key -text -noout
	#openssl prime prime
	#prime from rsa 2048 (prime1)
	#00:f9:39:fe:e9:20:9a:68:f2:4c:43:49:e1:c2:8e:
	#e2:31:7a:ec:6f:bd:16:80:f7:1d:14:a0:b3:76:0c:
	#62:05:bc:52:e6:50:bf:35:15:3c:ad:67:1b:be:1d:
	#a1:63:3d:63:e3:b2:1f:1d:a0:2a:f4:42:fd:f6:02:
	#b3:be:ba:09:fc:be:09:13:66:8f:4b:86:1e:14:d7:
	#a1:91:49:a9:d2:44:07:38:5f:30:b7:84:48:9f:5e:
	#29:3e:1d:d7:f4:72:56:12:d0:1f:ea:ed:07:2d:68:
	#79:ce:2b:3f:59:21:9e:df:72:b1:5c:5b:35:63:05:
	#42:72:03:f1:12:17:5d:bc:fd
	#int(..., 16)
	return 175012832246148469004952309893923119007504294868274830650101802243580016468616226644476369579140157420542034349400995694097261371077961674039236035533383172308367706779425637041402045013194820474112524204508905916696893254410707373670063475235242589213472899328698912258375583335003993274863729669402122894589

def get_private_key():
	#server private key
	return int(hashlib.sha512(str(time.time())).hexdigest(), 16)

def get_public_key(generator, private_key, prime):
	#server public key
	return pow(generator, private_key, prime)

def get_share_key_bytes(client_public_key, server_private_key, prime):
	#for get_rijndael_key
	return int_to_bytes(pow(client_public_key, server_private_key, prime))

def get_rijndael_key(share_key_bytes):
	rijndael_key_hex = ""
	for s in share_key_bytes[:32].lower():
		#if ord(s) > 57: rijndael_key_bytes += chr(ord(s)-48)
		#else: rijndael_key_bytes += s
		if s == "a": rijndael_key_hex += "1"
		elif s == "b": rijndael_key_hex += "2"
		elif s == "c": rijndael_key_hex += "3"
		elif s == "d": rijndael_key_hex += "4"
		elif s == "e": rijndael_key_hex += "5"
		elif s == "f": rijndael_key_hex += "6"
		else: rijndael_key_hex += s
	return rijndael_key_hex.decode("hex")

def encode(string, rijndael_obj):
	if not string:
		log_error("[error] encode error: string empty", string)
		return
	string_size = len(string)
	string += "\x00"*(16-len(string)%16)
	code = ""
	io = StringIO(string)
	with rijndael_obj.lock:
		while True:
			s = io.read(16)
			if not s:
				break
			code += rijndael_obj.encrypt(s)
	code_size = len(code)
	return pack_unsigned_int(code_size)+pack_unsigned_int(string_size)+code

def decode(code, rijndael_obj):
	if not code:
		log_error("[error] decode error: code empty", code)
		return
	if (len(code)-4) % 16:
		log_error("[error] decode error: length error", code.encode("hex"))
		return
	#0000000c 6677bcf44144b39e28281ae8777db574
	io = StringIO(code)
	string_size = io_unpack_int(io)
	string = ""
	with rijndael_obj.lock:
		while True:
			s = io.read(16)
			if not s:
				break
			string += rijndael_obj.decrypt(s)
	return string[:string_size]