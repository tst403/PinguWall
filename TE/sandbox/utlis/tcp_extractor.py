#!/usr/bin/python

from scapy.all import *


class TCP_FLAGS:
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80


def extract(txt, deli):
	ind = txt.index(deli)
	return txt[ind+len(deli):]


extract_first = lambda load : extract(extract(load, '\r\n\r\n'), '\r\n')


def find_last_http_index(stream):
	ind = 0

	for x in stream:
		if not x.haslayer(Raw) or\
		(x.haslayer(TCP) and x[TCP].flags & 1):
			return ind
		ind += 1

	return ind


def extract_last(txt, deli):
	ind = txt.rfind(deli)
	return txt[:ind]


extract_last_pack = lambda load: extract_last(extract_last(load, '\r\n\r\n'), '\r\n')


def download_tcp(stream):
	size = len(stream)
	first_ind = -1

	for i, pack in enumerate(stream):
		if pack.haslayer(TCP) and pack.haslayer(Raw):
			if '200 OK' in pack[Raw].load:
				first_ind = i
				break

	if first_ind == -1:
		return None

	newStream = stream[first_ind: ]

	last_http_index = find_last_http_index(newStream)
	newStream = newStream[:last_http_index]

	data = ''
	data += extract_first(newStream[0][Raw].load)

	for i, x in enumerate(newStream[1:]):
		if x.haslayer(Raw):
			if i != len(newStream) - 2:
				data += x[Raw].load
			else :
				data += extract_last_pack(x[Raw].load)

	return data


packs = rdpcap('favicon.pcapng')
sessions = packs.sessions()

assert(len(sessions) == 2)

streams = list(sessions.values())
serv_stream = streams[0] if len(streams[0]) < len(streams[1]) else streams[1]

data = download_tcp(serv_stream)

with open('test.ico', 'wb+') as f:
	f.write(data)
