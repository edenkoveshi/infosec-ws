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
#forward_to_http = ('10.0.2.2', 80)

class Forward:
	def __init__(self):
		self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.forward.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	def start(self, host, port):
		print "Forward Host: %s Port: %d" % (host,port)
		try:
			if(port != 80 and port != 21): #if it's FTP-DATA
				self.forward.bind(("",20)) #source port should be 20
			self.forward.connect((host, port))
			return self.forward
		except Exception, e:
			print e
			return False

class SimpleFTPDataServer:
	input_list = []
	channel = {}
	forwardIp = ""
	
	def __init__(self, host, port, forwardPort, forwardIp):
		self.forwardPort = forwardPort
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((host, port))
		self.server.listen(1)
		self.forwardIp = forwardIp
	
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

				#try: #added a try, so the proxy won't crash on client disconnection.
				self.data = self.s.recv(buffer_size)
				print "FTP-DATA Len: %d" % len(self.data)
				if len(self.data) == 0:
					self.on_close()
					#sys.exit(0)
					break
				else:
					self.on_recv()
					self.on_close()
					#sys.exit(0)
				#except:
					#break

	def on_accept(self):
		forward = Forward().start(self.forwardIp, self.forwardPort)
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
		sys.exit(0)

	def on_recv(self):
		data = self.data
		if(data.startswith("MZ")): #data from the server starts with "exe" magic bytes 
			self.on_close()
			
		print data
		self.channel[self.s].send(data)

class TheServer:
	def __init__(self, host, port, forwardPort):
		self.forwardPort = forwardPort
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind(('', port))
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
				except:
					print "Exception!"
					break

	def on_accept(self):
		forward = Forward().start('10.0.2.2', self.forwardPort)
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
		if(self.forwardPort == 80): #HTTP FILTERING
			if(data.startswith("HTTP/1.")): #data from the server starts with HTTP/1.
				if("Content-Length:" in data): #check if header exists
					if("\x0d" in data[data.find("Content-Length:") + len("Content-Length:") + 1:]):
						con_len = int(data[data.find("Content-Length:") + len("Content-Length:") + 1:].partition("\x0d\x0a")[0])
					else:
						con_len = int(data[data.find("Content-Length:") + len("Content-Length:") + 1:].partition("\x0a")[0])
					print "Got HTTP content length: %d" % con_len
					if(con_len > 5000): #close the connection if more than 5000 bytes
						self.on_close()
						print data
						return
				else: #header doesn't exist, close the connection.
					self.on_close()
					print data
					return
					
		elif(self.forwardPort == 21): #FTP Filtering
			if(data.startswith("PORT")): #data from the client starts with PORT
				if("\x0d" in data[data.find("PORT ") + len("PORT "):]):
					PORT = data[data.find("PORT ") + len("PORT "):].partition("\x0d\x0a")[0]
				else:
					PORT = data[data.find("PORT ") + len("PORT "):].partition("\x0a")[0]
				print "Got FTP PORT info: %s" % PORT
				s = PORT.split(",")
				portip = s[0]+"."+s[1]+"."+s[2]+"."+s[3]
				portnumber = int(s[4])*256 + int(s[5])
				ftp_data_server = SimpleFTPDataServer('0.0.0.0', portnumber,portnumber,portip)
				t = Thread(target=ftp_data_server.main_loop, name="FTP DATA PROXY")	
				t.start()
					
		print "ForwardPort: " + str(self.forwardPort) + " Data: " + data
		self.channel[self.s].send(data)

if __name__ == '__main__':
		http_server = TheServer('0.0.0.0', 8080,80)
		ftp_server = TheServer('0.0.0.0', 2121,21)
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
