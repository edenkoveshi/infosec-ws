import socket

IP = "127.0.0.1"
port = 55000

def main(args):
	#create an INET, STREAMing socket
	serversocket = socket.socket(
	    socket.AF_INET, socket.SOCK_STREAM)
	#bind the socket to a public host,
	# and a well-known port
	serversocket.bind((IP, port))
	#become a server socket
	serversocket.listen(5)

	while 1:
		#accept connections from outside
		(clientsocket, address) = serversocket.accept()
		print("Recieved connection from " + address)
		# send a thank you message to the client.  
		c.send('Thank you for connecting')
		# Close the connection with the client 
		c.close()


if __name__ == '__main__':
    import sys
    main(sys.argv)