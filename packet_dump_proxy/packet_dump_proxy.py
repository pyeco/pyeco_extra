#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import struct
import traceback
import socket
import threading
import time
import hashlib
from general import *
from site_packages import rijndael
try: from cStringIO import StringIO
except: from StringIO import StringIO
PROXY_ADDRESS = ("127.0.0.1", 1024)
PACKET_INIT = "\x00\x00\x00\x00\x00\x00\x00\x10"
PACKET_INIT_LENGTH = len(PACKET_INIT)
USE_LOGFILE = True
LOCAL_DATA_TYPE_NOT_PRINT = (
	"11f8", #自キャラの移動
	"0032", #接続確認(マップサーバとのみ) 20秒一回
	"0fa5", #戦闘状態変更通知
	"000a", #接続・接続確認
)
REMOTE_DATA_TYPE_NOT_PRINT = (
	"11f9", #キャラ移動アナウンス
	"0033", #接続先通知要求(ログインサーバ/0032)の応答
	"0fa6", #戦闘状態変更通知
	"000b", #接続・接続確認(s000a)の応答
)

def get_time():
	return time.strftime("%Y%m%d-%H%M%S", time.localtime())

class ProxyClient(threading.Thread):
	def __init__(self, s, src):
		threading.Thread.__init__(self)
		self.setDaemon(True)
		self.local = s
		self.remote = None
		self.remote_thread = None
		self.local_rijndael_obj = None
		self.remote_rijndael_obj = None
		self.generator = None
		self.prime = None
		self.src = src
		self.dst = None
		self.running = True
		self.log_lock = threading.RLock()
		self.local_send_lock = threading.RLock()
		self.remote_send_lock = threading.RLock()
		if USE_LOGFILE:
			self.wfile = open("%s.txt"%get_time(), "wb")
		else:
			self.wfile = None
		self.log("accept connection from %s"%str(self.src))
		self.start()
	
	def log(self, s):
		with self.log_lock:
			print s
			if self.wfile:
				self.wfile.write(s)
				self.wfile.write("\r\n")
	
	def local_sendall(self, s):
		with self.local_send_lock:
			self.local.sendall(s)
	
	def remote_sendall(self, s):
		with self.remote_send_lock:
			self.remote.sendall(s)
	
	def local_recvall(self, i):
		r = ""
		while i>0 and self.running:
			s = self.local.recv(i)
			if not s:
				raise EOFError
			i -= len(s)
			r += s
		return r
	
	def remote_recvall(self, i):
		r = ""
		while i>0 and self.running:
			s = self.remote.recv(i)
			if not s:
				raise EOFError
			i -= len(s)
			r += s
		return r
	
	def close(self):
		if not self.running:
			return
		self.local.shutdown(socket.SHUT_RDWR)
		self.local.close()
		self.remote.shutdown(socket.SHUT_RDWR)
		self.remote.close()
		self.running = False
		self.log("close connection from %s to %s"%(str(self.src), str(self.dst)))
		if self.wfile:
			self.wfile.close()
			self.wfile = None
	
	def get_data_list(self, data_pt):
		l = []
		data_pt_io = StringIO(data_pt)
		while self.running:
			length_bytes = data_pt_io.read(2)
			if not length_bytes:
				break
			data = data_pt_io.read(unpack_unsigned_short(length_bytes))
			if not data:
				break
			l.append((data[:2].encode("hex"), data[2:].encode("hex")))
		return l
	
	def remote_processer(self):
		while self.running:
			try:
				length = unpack_unsigned_int(self.remote_recvall(4))
				data_enc = self.remote_recvall(length+4)
				data_pt = decode(data_enc, self.remote_rijndael_obj)
				self.local_sendall(encode(data_pt, self.local_rijndael_obj))
				for i, j in self.get_data_list(data_pt):
					if i in REMOTE_DATA_TYPE_NOT_PRINT:
						continue
					self.log("recv %s %s"%(i, j))
			except (EOFError, socket.error):
				break
			except:
				self.log(traceback.format_exc())
				break
		self.close()
	
	def local_processer(self):
		while self.running:
			try:
				length = unpack_unsigned_int(self.local_recvall(4))
				data_enc = self.local_recvall(length+4)
				data_pt = decode(data_enc, self.local_rijndael_obj)
				self.remote_sendall(encode(data_pt, self.remote_rijndael_obj))
				for i, j in self.get_data_list(data_pt):
					if i in LOCAL_DATA_TYPE_NOT_PRINT:
						continue
					self.log("send %s %s"%(i, j))
			except (EOFError, socket.error):
				break
			except:
				self.log(traceback.format_exc())
				break
		self.close()
	
	def setup_proxy(self):
		ver = ord(self.local_recvall(1))
		if ver == 5:
			if self.local_recvall(2) != "\x01\x00":
				raise ValueError("wrong socks value")
			self.local_sendall("\x05\x00")
			head = self.local_recvall(4)
			mode, addrtype = ord(head[1]), ord(head[3])
			if mode != 1:
				raise ValueError("mode %s not tcp"%mode)
			if addrtype == 1: #ipv4
				addr = socket.inet_ntoa(self.local_recvall(4))
			elif addrtype == 3: #domain
				addr = self.local_recvall(ord(self.local_recvall(1)))
			else:
				raise ValueError("unknow addrtype %s"%addrtype)
			port = unpack_unsigned_short(self.local_recvall(2))
			self.local_sendall("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
		elif ver == 4:
			data = self.local_recvall(7)
			self.local.recv(1024)
			addr = socket.inet_ntoa(data[3:7])
			port = unpack_unsigned_short(data[1:3])
			self.local_sendall("\x00\x5a"+data[:7])
		else:
			raise ValueError("unknow socks version %s"%ver)
		self.log("create remote connection to (%s, %s)"%(addr, port))
		self.dst = (addr, port)
		self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.remote.connect((addr, port))
	
	def setup_remote_processer(self):
		self.remote_thread = threading.Thread(target=self.remote_processer, args=())
		self.remote_thread.setDaemon(True)
		self.remote_thread.start()
	
	def setup_remote_encryption(self):
		self.remote_sendall(PACKET_INIT)
		head = self.remote_recvall(4)
		generator_length = unpack_unsigned_int(self.remote_recvall(4))
		generator = int(self.remote_recvall(generator_length))
		prime_length = unpack_unsigned_int(self.remote_recvall(4))
		prime = bytes_to_int(self.remote_recvall(prime_length))
		server_public_key_length = unpack_unsigned_int(self.remote_recvall(4))
		server_public_key = bytes_to_int(self.remote_recvall(prime_length))
		self.log("remote encryption: generator: %s, prime: %s, server_public_key: %s"%(
			generator, prime, server_public_key,
		))
		client_private_key = get_private_key()
		client_public_key = get_public_key(generator, client_private_key, prime)
		client_public_key_bytes = int_to_bytes(client_public_key)
		self.remote_sendall(pack_unsigned_int(len(client_public_key_bytes)))
		self.remote_sendall(client_public_key_bytes)
		self.log("remote encryption: client_private_key: %s, client_public_key: %s"%(
			client_private_key, client_public_key,
		))
		share_key = get_share_key_bytes(server_public_key, client_private_key, prime)
		rijndael_key = get_rijndael_key(share_key)
		self.log("remote encryption: share_key: %s, rijndael_key: %s"%(
			share_key, rijndael_key.encode("hex"),
		))
		self.remote_rijndael_obj = rijndael.rijndael(rijndael_key, block_size=16)
		self.remote_rijndael_obj.lock = threading.RLock()
		self.generator = generator
		self.prime = prime
	
	def setup_local_encryption(self):
		if self.local_recvall(PACKET_INIT_LENGTH) != PACKET_INIT:
			raise ValueError("packet != PACKET_INIT")
		generator = self.generator
		prime = self.prime
		prime_bytes = int_to_bytes(prime)
		self.log("local encryption: generator: %s prime: %s"%(generator, prime))
		server_private_key = get_private_key()
		server_public_key = get_public_key(generator, server_private_key, prime)
		server_public_key_bytes = int_to_bytes(server_public_key)
		self.log("local encryption: server_private_key: %s, server_public_key %s"%(
			server_private_key, server_public_key,
		))
		packet_key_exchange = "".join((
			pack_unsigned_int(0),
			pack_unsigned_int(len(str(generator)))+str(generator),
			pack_unsigned_int(len(prime_bytes))+prime_bytes,
			pack_unsigned_int(len(server_public_key_bytes))+server_public_key_bytes,
		))
		self.local_sendall(packet_key_exchange)
		client_public_key_length = unpack_unsigned_int(self.local_recvall(4))
		client_public_key = bytes_to_int(self.local_recvall(client_public_key_length))
		share_key = get_share_key_bytes(client_public_key, server_private_key, prime)
		rijndael_key = get_rijndael_key(share_key)
		self.log("local encryption: share_key: %s, rijndael_key: %s"%(
			share_key, rijndael_key.encode("hex"),
		))
		self.local_rijndael_obj = rijndael.rijndael(rijndael_key, block_size=16)
		self.local_rijndael_obj.lock = threading.RLock()
	
	def run(self):
		try:
			self.setup_proxy()
			self.setup_remote_encryption()
			self.setup_local_encryption()
			self.setup_remote_processer()
			self.local_processer()
		except (EOFError, socket.error):
			pass
		except:
			self.log(traceback.format_exc())

class ProxyServer(threading.Thread):
	def __init__(self, addr):
		threading.Thread.__init__(self)
		self.setDaemon(True)
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind(addr)
		self.socket.listen(10)
		print "start proxy server %s"%str(addr)
		self.start()
	
	def run(self):
		while True:
			try:
				ProxyClient(*self.socket.accept())
			except:
				print traceback.format_exc()

if __name__ == "__main__":
	proxy_server = ProxyServer(PROXY_ADDRESS)
	while True:
		time.sleep(1)