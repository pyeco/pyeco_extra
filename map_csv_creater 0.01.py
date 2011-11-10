#!/bin/python
# -*- coding: utf-8 -*-
from __future__ import division
import os
import sys
import csv

map_data_folder_path = "z:/eco/unpack/data/map/map.dat"
map_name_csv_path =  "z:/eco/unpack/data/xls/table.dat/mapname.csv"
os.chdir(sys.path[0])
sysenc = sys.getfilesystemencoding()
mapnamedic = {}
reader = csv.reader(file(map_name_csv_path, "rb"))
for row in reader:
	mapnamedic[row[0]] = row[1].decode("shift-jis").encode("utf-8")
dic = {}
for a,b,c in os.walk(map_data_folder_path):
	for x in c:
		if x[-4:] == ".map":
			f = open(a+"/"+x,"rb")
			b = f.read()
			f.close()
			#mapid = str(b[4:12])
			mapid = str(x[:-4])
			mapcenterx = str(int(b[36:37].encode("hex"),16) / 2).replace(".0","")
			mapcentery = str(int(b[38:39].encode("hex"),16) / 2).replace(".0","")
			if str(mapcenterx) == "0":
				mapcenterx = "128"
			if str(mapcentery) == "0":
				mapcentery = "128"
			t = mapid+","
			if mapnamedic.get(mapid) != None:
				t = t+mapnamedic[mapid] + ","
			else:
				t = t+mapid+","
			t = t+mapcenterx+","
			t = t+mapcentery+","
			dic[mapid] = t
			print t.decode("utf-8").encode(sysenc)

w = "#マップＩＤ,マップ名,中心座標ｘ,中心座標ｙ,"
s = sorted(dic,key=int)
for x in s:
	w = w+"\n"+dic[x]
f = open("map.csv","w")
f.write(w)
f.close



