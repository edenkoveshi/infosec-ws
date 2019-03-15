import scapy.all as S

#https://null-byte.wonderhowto.com/how-to/build-ftp-password-sniffer-with-scapy-and-python-0169759/
#https://medium.com/@ismailakkila/black-hat-python-parsing-http-payloads-with-scapy-d937d01af9b1

THIS_IP = "10.0.2.5"

def pkt_filter(pkt):
	#print(pkt.summary)
	if S.IP in pkt:
		if pkt[S.IP].dst != THIS_IP:
			print("Not destined for this IP!")
			return False
		if S.TCP in packet:
			print("Packet recieved!")
			return True
			if pkt[S.TCP].dport == 21 or pkt[S.TCP].sport == 21:
				return True
			if pkt[S.TCP].dport == 80 or pkt[S.TCP].sport == 80:
				return True
	return False

def handle_pkt(pkt):
	data = pkt[S.TCP].payload
	print(data)

	#print(pkt.summary)

	#if pkt[S.TCP].dport == 80 or pkt[S.TCP].sport == 80:

	res = check_http_packet(pkt,data)
	if res[0] == 0:
		return res[1]
	else:
		new_pkt = pkt.copy()
		new_pkt[S.IP].dst = pkt[S.IP].src
		new_pkt[S.IP].src = THIS_IP
		del new_pkt[S.IP].chksum
		del new_pkt[S.TCP].chksum #delete checksums so they will be recreated and corrected upon send
		S.send(new_pkt)
		return "Packet passed!"


	#elif pkt[S.TCP].dport == 21 or pkt[S.TCP].sport == 21:
	#	return "boo"

def check_http_packet(pkt,data):
		idx = data.find("\r\n\r\n")
		if idx == -1:
			return [0,"Packet dropped, end of headers not found"]
		_idx = data.find("\r\n\r\n",idx)
		if _idx != -1:
			return [0,"Packet dropped, double CLRF found twice"]

		headers = data[:idx]
		content = data[idx + len("\r\n\r\n"):]

		content_length_idx = headers.find("Content-Length:")
		if content_length_idx == -1:
			return [0,"Packet dropped, no content length field"]

		content_length_header = headers[content_length_idx:].split('\r\n\r\n')[0] #This is a crappy hack to extract the header
		if len(content_length_header) < len("Content-Length: 0"): #0 is arbitrary, this the minimal length of a content length header
			return [0,"Packet dropped, content length header corrupted"]

		#HTTP does not define a maximal length and so I won't, but I believe it is recommended

		s = int(content_length_header.split(':')[0].strip())
		if s != len(content):
			return [0,"Packet dropped, content length mismatch"]

		if s > 2000:
			if s[:8] == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
				return [0,"Packet dropped, large Office file not permitted"]

def main(args):
	S.sniff(lfilter=pkt_filter,prn=handle_pkt)

if __name__ == '__main__':
    import sys
    main(sys.argv)