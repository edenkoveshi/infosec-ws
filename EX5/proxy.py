#!/usr/bin/python
# http://voorloopnul.com/blog/a-python-proxy-in-less-than-100-lines-of-code/
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license
import socket
import select
import time
import sys
import os
import signal
import string
import dlp
from threading import *

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001
ALLOWED_LENGTH = 2000
MAGIC = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" #https://en.wikipedia.org/wiki/List_of_file_signatures
MAGIC_OFFSET = 0
HTTP_PORT = 8080
FTP_PORT = 2021
SMTP_PORT = 2525
HOST_2 = '10.0.2.2'

class Forward:
	def __init__(self):
		self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.forward.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	def start(self, host, port):
		print "Forward Host: %s Port: %d" % (host,port)
		try:
			self.forward.connect((host, port))
			return self.forward
		except Exception, e:
			print e
			return False

class TheServer:
	def __init__(self, host, port, forward_port):
		self.forward_port = forward_port
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((host, port))
		self.server.listen(200)
		self.input_list = []
		self.channel = {}
		self.__data_flag__ = False
		self.ftp_state = "FTP_NONE"

	def main_loop(self):
		self.input_list.append(self.server)
		while 1:
			time.sleep(delay)
			ss = select.select
			inputready, outputready, exceptready = ss(self.input_list, [], [])
			for self.s in inputready:
				if self.s == self.server:
					self.on_accept()
					break

				try: #added a try, so the proxy won't crash on client disconnection.
					self.data = self.s.recv(buffer_size)
					
					if len(self.data) == 0:
						self.on_close()
						break
					else:
						self.on_recv()
				except Exception, e:
					print e
					break

	def on_accept(self):
		forward = Forward().start(HOST_2, self.forward_port)
		clientsock, clientaddr = self.server.accept()
		if forward:
			print clientaddr, "has connected"
			self.input_list.append(clientsock)
			self.input_list.append(forward)
			self.channel[clientsock] = forward
			self.channel[forward] = clientsock
		else:
			print "Can't establish connection with remote server.",
			print "Closing connection with client side", clientaddr
			clientsock.close()

	def on_close(self):
		print self.s.getpeername(), "has disconnected"
		#remove objects from input_list
		self.input_list.remove(self.s)
		self.input_list.remove(self.channel[self.s])
		out = self.channel[self.s]
		# close the connection with client
		self.channel[out].close()  # equivalent to do self.s.close()
		# close the connection with remote server
		self.channel[self.s].close()
		# delete both objects from channel dict
		del self.channel[out]
		del self.channel[self.s]

	def on_recv(self):
		data = self.data
		# here we can parse and/or modify the data before send forward
		if(self.forward_port == 80): #HTTP Filtering
			if(self.inspect_http() == False):
				self.on_close()
				return
					
		elif(self.forward_port == 21): #FTP Filtering
			if(self.inspect_ftp() == False):
				print "ftp inspection failed"
				self.on_close()
				return
					
		elif(self.forwardPort == 25): #SMTP Filtering
			if (data[0] == '5'): #error
				self.__data_flag__ = False
			if (self.__data_flag__ and data[0] not in string.digits):
				self.__data_flag__ = False
				code = data
				print "Code: {}".format(code)
				if("\x0d\x0a.\x0d\x0a" in data or data == ".\x0d\x0a"): # all in one packet or multiple packets for data and this is the last one
					self.__data_flag__ = False
				if (dlp.isCode(code)):
					print "Code detected!"
					self.on_close()
					print code
					return

			if (data.upper().startswith("DATA") and len(data) < 8):
				print "SMTP DATA INCOMING"
				self.__data_flag__ = True

		print "forward_port: " + str(self.forward_port) + " Data: " + data
		self.channel[self.s].send(data)

	def inspect_http(self):
		data = self.data
		if("Content-Length:" in data): #check if header exists
			idx = data.find("Content-Length:")
			clen = len("Content-Length:")
			if("\x0d" in data[idx + clen + 1:]):
				con_len = int(data[idx + clen + 1:].partition("\x0d\x0a")[0])
			else:
				con_len = int(data[idx + clen + 1:].partition("\x0a")[0])
			print "Got HTTP content length: %d" % con_len
			if(data.startswith("GET ")): #data from the server starts with HTTP/1.
				if(con_len > ALLOWED_LENGTH): #"unallowed" length
					body = data.split('\r\n\r\n')[1]
					if(body[MAGIC_OFFSET:MAGIC_OFFSET + len(MAGIC)] == MAGIC): #office file detected
						print body
						return False

			elif(data.startswith("POST ")): #POST request, check data with dlp
				start_idx = data.find('\x0d\x0a'*2)
				if (start_idx != -1):
					code = data[start_idx+4:]
					if (dlp.isCode(code)):
						print "Code detected!"
						print code
						return False
			elif(data.startswith("PUT ")): #block hasicorp consul rce attack
				if('X-Consul-Token' in data):
					if('script' in data):
						print "Attack detected!"
						return False
		else: #header doesn't exist, close the connection.
				print data
				return False
		return True


	def inspect_ftp(self):
		data = self.data
		print data
		if(data.startswith("USER ")): #beginning
			if(self.ftp_state != "FTP_NONE"):
				print "USER failed"
				return False
			else:
				self.ftp_state = "FTP_USER_SENT"
		elif(data.startswith("331 ")): #user ok,waiting for password
			if(self.ftp_state == "FTP_USER_SENT"):
				self.ftp_state = "FTP_USER_OK"
			else:
				print "331 failed"
				return False
		elif(data.startswith("PASS ")): #password sent
			if(self.ftp_state == "FTP_USER_OK"):
				self.ftp_state = "FTP_PASSWORD_SENT"
			else:
				print "PASS failed"
				return False
		elif(data.startswith("230 ")): #authorized
			if(self.ftp_state == "FTP_PASSWORD_SENT"):
				self.ftp_state = "FTP_CONN_ESTABLISHED"
			else:
				print "230 failed"
				return False
		elif(data.startswith("PORT ")):
			if(self.ftp_state == "FTP_CONN_ESTABLISHED"):
				self.ftp_state = "FTP_PORT_SENT"
			else:
				print "self.ftp_state = %s" %self.ftp_state
				print "PORT failed"
				return False
		elif(data.startswith("150 ") or data.startswith("STOR") or data.startswith("RETR")): #opening port for transfer
			if(self.ftp_state != "FTP_FILE_TRANSFER"):
				print "Data transfer failed"
				return False
			elif(data.find("226") != -1): 
				self.ftp_state = "FTP_CONN_ESTABLISHED"
		elif(data.startswith("226")): #transfer done
			if(self.ftp_state == "FTP_FILE_TRANSFER"):
				self.ftp_state = "FTP_CONN_ESTABLISHED"
			else:
				print "226 failed"
				return False
		elif(data.startswith("221 ")): #communcation ended
			self.ftp_state = "FTP_NONE"
		elif(data.startswith("200 ")):
			if(self.ftp_state == "FTP_PORT_SENT"):
				self.ftp_state = "FTP_FILE_TRANSFER"
			elif(self.ftp_state != "FTP_CONN_ESTABLISHED" and self.ftp_state != "FTP_NONE"):
				print "200 failed"
				return False
		return True


if __name__ == '__main__':
		http_server = TheServer('0.0.0.0',HTTP_PORT,80)
		ftp_server = TheServer('0.0.0.0', FTP_PORT,21)
		smtp_server = TheServer('0.0.0.0', SMTP_PORT,25)
		t1 = Thread(target=http_server.main_loop, name="HTTP PROXY")	
		t2 = Thread(target=ftp_server.main_loop, name="FTP PROXY")
		t3 = Thread(target=smtp_server.main_loop, name="SMTP PROXY")
		
		t1.start()
		t2.start()
		t3.start()
		while 1:
			try:
				time.sleep(delay)
			except KeyboardInterrupt:
				print "Ctrl C - Stopping server"
				os.kill(os.getpid(), signal.SIGKILL)
