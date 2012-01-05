#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import time
import hashlib
import getpass
import traceback
import subprocess
import ConfigParser
import ctypes
try: from cStringIO import StringIO
except: from StringIO import StringIO

def check_eco_exe():
	if not os.path.exists("eco.exe"):
		raise Exception("error: eco.exe not found...")

def get_config_io(path):
	with open(path, "rb") as r:
		config = r.read()
	if config.startswith("\xef\xbb\xbf"):
		config = config[3:]
	return StringIO(config.replace("\r\n", "\n"))

def get_config(path=None):
	cfg = ConfigParser.SafeConfigParser()
	if path:
		cfg.readfp(get_config_io(path))
	return cfg

def get_last_user_name():
	try:
		cfg = get_config("pyecolauncher.ini")
		return cfg.get("main", "last_user_name")
	except:
		return ""

def set_last_user_name(name):
	cfg = get_config()
	cfg.add_section("main")
	cfg.set("main", "last_user_name", name)
	cfg.write(open("pyecolauncher.ini", "wb"))

def main():
	check_eco_exe()
	user_name = get_last_user_name()
	user_password = ""
	print "default user name:", user_name
	if user_name:
		input_text = raw_input(
			"please input user name or press return to use [%s]: "%user_name).strip()
		if input_text:
			user_name = input_text
	else:
		while not user_name:
			user_name = raw_input("please input user name: ").strip()
		set_last_user_name(user_name)
	while not user_password:
		user_password = getpass.getpass(
			"please input user password [hidden input]: ").strip()
	command = "eco.exe /launch /path %s -u:%s -p:%s"%(
				os.getcwd(),
				user_name,
				hashlib.md5(user_password).hexdigest()
				)
	#print command
	subprocess.Popen(filter(None, command.split(" ")), shell=False)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		pass
	except:
		print traceback.format_exc()
		input()