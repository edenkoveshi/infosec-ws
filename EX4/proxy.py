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
HOST_2 = '10.0.2.2'

class TheServer:
	def __init__(self, host, port, forward_port):
		self.forward_port = forward_port
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((host, port))
		self.server.listen(200)
		self.input_list = []
		self.channel = {}

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
		try:
			self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.forward.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.forward.connect((HOST_2, self.forward_port))
			clientsock, clientaddr = self.server.accept()
			#if forward:
			print clientaddr, "has connected"
			self.input_list.append(clientsock)
			self.input_list.append(self.forward)
			self.channel[clientsock] = self.forward
			self.channel[self.forward] = clientsock
		except Exception,e:
			#print e
			return

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
		if(self.forward_port == 80): #HTTP FILTERING
			if(self.inspect_http() == False):
				self.on_close()
				return
					
		elif(self.forward_port == 21): #FTP Filtering
			if(self.inspect_ftp() == False):
				self.on_close()
				return
					
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
			if(data.startswith("HTTP/1 ")): #data from the server starts with HTTP/1.
				if(con_len > ALLOWED_LENGTH): #"unallowed" length
					body = data.split('\r\n\r\n')[1]
					if(body[MAGIC_OFFSET:MAGIC_OFFSET + len(MAGIC)] == MAGIC): #office file detected
						print body
						return False
		else: #header doesn't exist, close the connection.
			print "no content header"
			print data
			return False
		return True


	def inspect_ftp(self):
		data = self.data
		#print data
		if(data.startswith("USER ")): #beginning
			if(self.ftp_state != "FTP_NONE"):
				print "USER failed"
				self.ftp_state = "FTP_NONE"
				return False
			else:
				self.ftp_state = "FTP_USER_SENT"
		elif(data.startswith("331 ")): #user ok,waiting for password
			if(self.ftp_state == "FTP_USER_SENT"):
				self.ftp_state = "FTP_USER_OK"
			else:
				self.ftp_state = "FTP_NONE"
				print "331 failed"
				return False
		elif(data.startswith("PASS ")): #password sent
			if(self.ftp_state == "FTP_USER_OK"):
				self.ftp_state = "FTP_PASSWORD_SENT"
			else:
				self.ftp_state = "FTP_NONE"
				print "PASS failed"
				return False
		elif(data.startswith("230 ")): #authorized
			if(self.ftp_state == "FTP_PASSWORD_SENT"):
				self.ftp_state = "FTP_CONN_ESTABLISHED"
			else:
				self.ftp_state = "FTP_NONE"
				print "230 failed"
				return False
		elif(data.startswith("PORT ")):
			if(self.ftp_state == "FTP_CONN_ESTABLISHED"):
				self.ftp_state = "FTP_PORT_SENT"
			else:
				self.ftp_state = "FTP_NONE"
				print "self.ftp_state = %s" %self.ftp_state
				print "PORT failed"
				return False
		elif(data.startswith("150 ") or data.startswith("STOR") or data.startswith("RETR")): #opening port for transfer
			if(self.ftp_state != "FTP_FILE_TRANSFER"):
				print "Data transfer failed"
				self.ftp_state = "FTP_NONE"
				return False
			elif('226' in data): 
				self.ftp_state = "FTP_CONN_ESTABLISHED"
		elif(data.startswith("226")): #transfer done
			if(self.ftp_state == "FTP_FILE_TRANSFER"):
				self.ftp_state = "FTP_CONN_ESTABLISHED"
			else:
				self.ftp_state = "FTP_NONE"
				print "226 failed"
				return False
		elif(data.startswith("221 ")): #communcation ended
			self.ftp_state = "FTP_NONE"
		elif(data.startswith("200 ")):
			if(self.ftp_state == "FTP_PORT_SENT"):
				self.ftp_state = "FTP_FILE_TRANSFER"
			elif(self.ftp_state != "FTP_CONN_ESTABLISHED" and self.ftp_state != "FTP_NONE"):
				self.ftp_state = "FTP_NONE"
				print "200 failed"
				return False
		return True

if __name__ == '__main__':
		http_server = TheServer('0.0.0.0',HTTP_PORT,80)
		ftp_server = TheServer('0.0.0.0', FTP_PORT,21)
		t1 = Thread(target=http_server.main_loop, name="HTTP PROXY")	
		t2 = Thread(target=ftp_server.main_loop, name="FTP PROXY")
		
		t1.start()
		t2.start()
		while 1:
			try:
				time.sleep(delay)
			except KeyboardInterrupt:
				print "Ctrl C - Stopping server"
				os.kill(os.getpid(), signal.SIGKILL)
