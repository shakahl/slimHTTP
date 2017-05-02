import pwd, grp
import struct
import re
import zlib
import importlib.machinery
import imp
import json
from socket import *
from time import time
from mimetypes import guess_type
from base64 import b64decode as bdec
from base64 import b64encode as benc
from os import getuid, setgroups, setgid, setuid, umask, getcwd, chdir
from os.path import abspath, isfile, basename, dirname, splitext
from select import epoll, EPOLLIN, EPOLLOUT, EPOLLHUP

from collections import OrderedDict as OD
from random import randint

## == References:
def drop_privileges(uid_name='alarm', gid_name='alarm'):
	if getuid() != 0:
		# We're not root so, like, whatever dude
		return

	# Get the uid/gid from the name
	running_uid = pwd.getpwnam(uid_name).pw_uid
	running_gid = grp.getgrnam(gid_name).gr_gid

	# Remove group privileges
	setgroups([])

	# Try setting the new uid/gid
	setgid(running_gid)
	setuid(running_uid)

	# Ensure a very conservative umask
	old_umask = umask(0o077)

#coreSock = socket(AF_INET, SOCK_DGRAM)
coreSock = socket()
coreSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
coreSock.bind(('0.0.0.0', 80))
coreSock.setblocking(0)
coreSock.listen(1)

poll = epoll()
poll.register(coreSock.fileno(), EPOLLIN)

socks = {}

data_govenor = {}
data_queue = {}

__dir__ = getcwd()
drop_privileges()
#chdir(__dir__)



def deflate(data, compresslevel=9):
	compress = zlib.compressobj(
			compresslevel,		# level: 0-9
			zlib.DEFLATED,		# method: must be DEFLATED
			-zlib.MAX_WBITS, 	# window size in bits:
						#   -15..-8: negate, suppress header
						#   8..15: normal
						#   16..30: subtract 16, gzip header
			zlib.DEF_MEM_LEVEL,	# mem level: 1..8/9
			0			# strategy:
						#   0 = Z_DEFAULT_STRATEGY
						#   1 = Z_FILTERED
						#   2 = Z_HUFFMAN_ONLY
						#   3 = Z_RLE
						#   4 = Z_FIXED
	)
	deflated = compress.compress(data)
	deflated += compress.flush()
	return deflated

def parse_py(path, content=b'', request=None):
	filename = basename(path)
	fname, fext = filename.rsplit('.',1)

	if isfile(fname+'.py'):
		namespace = fname.replace('/', '_').strip('\\/;,. ')
		#print('    Emulating ElasticSearch via script:',namespace,fullPath.decode('utf-8')+'.py')
		loader = importlib.machinery.SourceFileLoader(namespace, dirname(path) + '/' + fname +'.py')
		handle = loader.load_module(namespace)
		imp.reload(handle)
		ret = handle.main(request=request)

		if len(content) > 0:
			if bytes('%%'+fname+'.py', 'UTF-8') in content:
				for key, val in ret.items():
					content = content.replace(bytes('%%'+fname+'.py::'+key+'%%', 'UTF-8'), bytes(json.dumps(val), 'UTF-8'))
		else:
			content = ret['body']

	return content

def parse_transfered_bytes(data):
	if b'\r\n\r\n' in data:
		GET, POST = data.split(b'\r\n\r\n', 1)
		headers = {}
		mime_type = 'text/plain'
		status = 404
		status_codes = {200 : 'HTTP/1.0 200 OK',
				404 : 'HTTP/1.0 404 Not Found'}

		# TODO: Rename GET to Headers or something, for petes sake.		
		for item in GET.split(b'\r\n'):
			if len(item) <= 0: continue

			if item[:5] == b'GET /' or item[:6] == b'POST /':
				trash, url, trash = item.split(b' ',2)
				url = url.replace(b'./', b'/').decode('utf-8')
				print('  Trying to fetch:', url)
				path = abspath('./' + url)
				request = None
				if '?' in path:
					path, request = path.split('?',1)
				extension = splitext(path)[1]

				if isfile(path):
					if extension == '.py':
						if item[:6] == b'POST /':
							if not request:
								request = {}
							print(POST)
							for post_item in POST.split(b'&'):
								if len(post_item) <= 0: continue
								print(post_item)
								key, val = post_item.split(b'=',1)
								request[key] = val
						ret_data = parse_py(path, request=request)
						mime_type = 'text/html'
						status = 200
						if type(ret_data) is str: ret_data = bytes(ret_data, 'UTF-8')
					else:
						mime_type = guess_type(path)[0]
						status = 200
						print('  Delivering with mime-type:',mime_type)

						with open(path, 'rb') as fh:
							ret_data = fh.read()

						if mime_type in ('text/plain', 'text/html'):
							ret_data = parse_py(path, ret_data)
				else:
					ret_data = b'Sorry, 404 mate.'
					print('  - 404 could not be found:', path)
			elif b': ' in item:
				key, val = item.split(b': ',1)
				headers[key] = val
			else:
				print('Suspicious header item:', item)

		ret_data = deflate(ret_data)

		response = status_codes[status] + '\r\n'
		response += 'Accept-Ranges: none\r\n'
		response += 'Access-Control-Allow-Origin: *\r\n'
		response += 'Cache-Control: max-age=300\r\n'
		#response += 'Connection: keep-alive\r\n'
		response += 'Content-Encoding: deflate\r\n'
		response += 'Content-Length: ' + str(len(ret_data)) + '\r\n'
		response += 'Content-Type: ' + mime_type + '; charset=utf-8\r\n'
		response += '\r\n'

		response = bytes(response, 'UTF-8')
		response += ret_data
		#response += zlib.decompress(ret_data, 16+zlib.MAX_WBITS)

		return 'HTTP', response
	else:
		return -1

while True:
	events = poll.poll(1)
	for fileno, event in events:
		if event is EPOLLIN:
			if fileno == coreSock.fileno():
				ns, na = coreSock.accept()
				print('accepting',na)
				socks[ns.fileno()] = ns
				poll.register(ns.fileno(), EPOLLIN)
			else:
				data_govenor[fileno] = time()
				if fileno in data_queue:
					data = socks[fileno].recv(8192)
					if len(data) == 0:
						poll.unregister(fileno)
						socks[fileno].close()
						del(socks[fileno])
						if len(data_queue[fileno]) != 0:
							print('Lost some data:', len(data_queue[fileno]))
						if fileno in data_queue:
							del(data_queue[fileno])
						print('Unexpectedly dropped client due to no data recieved.')
						continue
					else:
						print('Adding to data queue')
						data_queue[fileno] += data
				else:
					data_queue[fileno] = socks[fileno].recv(8192)

				if len(data_queue[fileno]) == 0:
					break

				parsed = parse_transfered_bytes(data_queue[fileno])
				if parsed is -1:
					continue
				else:
					if fileno in data_queue:
						del(data_queue[fileno])

				decoded, response = parsed
				if decoded == 'HTTP':
					socks[fileno].send(response)
					poll.unregister(fileno)
					socks[fileno].close()
					del(socks[fileno])
					if fileno in data_queue:
						del(data_queue[fileno])
				else:
					print('Decoded:', [decoded])

		else:
			print('Unknown event:',event)
