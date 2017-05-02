from socket import *
from ssl import wrap_socket
from select import epoll, EPOLLIN, EPOLLOUT, EPOLLHUP
from os.path import isfile, abspath
from mimetypes import guess_type # TODO: security consern, doesn't handle bytes,
#								   requires us to decode the string before guessing type.
from json import dumps
from time import time, sleep
logs = {}

mute_level = 1

def log(*args, **kwargs):
	if not 'level' in kwargs:
		kwargs['level'] = 0 # info, 1 = warn, 2 = error, 3+ temporary/custom errors.

	if kwargs['level'] < mute_level: return

	source = args[0] if len(args) > 1 else kwargs['application'] if 'application' in kwargs else '?' # argv[0] / kwargs['application'] / ''
	function = args[1] if len(args) > 2 else kwargs['function'] if 'function' in kwargs else '?'
	message = ' '.join(args[2:]) if len(args) >= 3 else ' '.join(args[1:]) if len(args) >= 2 else ' '.join(args)

	if 'once' in kwargs:
		if args[-1] in logs: return True

		logs[message] = time()

	print('[{source}].{function}() [{level}] {msg}'.format(**{'source': source, 'function': function, 'level': kwargs['level'], 'msg' : message}))

def drop_privileges():
	return True

class http_cliententity():
	def __init__(self, parent, sock, addr=None):
		self.info = {'addr' : addr,
					'data' : b''}

		self.parent = parent
		self.socket = sock
		self.id = self.info['addr'][0]

	def recv(self, buffert=8192):
		if self.parent.poll(fileno=self.socket.fileno()):
			d = self.socket.recv(buffert)
			if len(d) == 0:
				self.close()
				return None
			self.info['data'] += d
			return len(self.info['data'])
		return None

	#def id(self):
	#	return self.info['addr'][0] 

	def close(self):
		self.socket.close()
		return True

	def respond(self, d):
		if d is None: d = b'HTTP/1.1 200 OK\r\n\r\n'

		if type(d) != bytes:
			d = bytes(d, 'UTF-8')

		#print('>', d)
		self.socket.send(d)
		return True


class http_serve():
	def __init__(self):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.bind(('', 80))

		self.pollobj = epoll()
		self.sockets = {}

		while drop_privileges() is None:
			log('slimHTTP', 'http_serve', 'Waiting for privileges to drop.', once=True)

		self.sock.listen(10)
		self.main_so_id = self.sock.fileno()
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

	def accept(self, client_trap=http_cliententity):
		events = self.poll(1)
		if self.main_so_id in events:
			ns, na = self.sock.accept()
			log('slimHTTP', 'http_server', 'Accepting new client: {addr}'.format(**{'addr' : na[0]}))
			ns_fileno = ns.fileno()
			if ns_fileno in self.sockets:
				self.sockets[ns_fileno].close()
				del self.sockets[ns_fileno]

			self.pollobj.register(ns_fileno, EPOLLIN)
			self.sockets[ns_fileno] = http_cliententity(self, ns, na)
			return self.sockets[ns_fileno]
		return None

	def poll(self, timeout=10, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self, fileno=None):
		if fileno:
			try:
				self.pollobj.unregister(fileno)
			except FileNotFoundError:
				pass # Already unregistered most likely.
			self.sockets[fileno].close()
			return True
		else:
			for fileno in self.sockets:
				try:
					self.pollobj.unregister(fileno)
					self.sockets[fileno].socket.close()
				except:
					pass
			self.pollobj.unregister(self.main_so_id)
			self.sock.close()

class https_serve():
	def __init__(self):
		pass

def get_file(headers, *args, **kwargs):
	if b'path' in headers:
		relpath = abspath(b'./' + abspath(headers[b'path']))
		if isfile( relpath ):
			with open(relpath, 'rb') as fh:
				data = fh.read()
			
			return data
	return None

class http_request():
	def __init__(self, client_info):
		""" A dummy parser that will return 200 OK on everything. """
		self.info = client_info
		self.headers = {}
		self.payload = b''
		self.methods = {b'GET' : self.GET, b'PUT' : self.PUT}
		self.ret_code = 200
		self.ret_data = {200 : b'HTTP/1.1 200 OK\r\n',
						 404 : b'HTTP/1.1 404 Not Found\r\n'}
		self.ret_headers = {} # b'Content-Type' : 'plain/text' ?

	def local_file(self):
		path, data = get_file(self.headers)
		if data:
			mime = guess_type(path.decode('UTF-8'))[0] #TODO: Deviates from bytes pattern. Replace guess_type()
			self.ret_headers[b'Content-Type'] = bytes(mime, 'UTF-8') if mime else b'plain/text'
		else:
			self.ret_code = 404
		return data

	def PUT(self):
		return None

	def GET(self):
		return self.local_file()

	def build_headers(self):
		x = b''
		if self.ret_code in self.ret_data:
			x += self.ret_data[self.ret_code]# + self.build_headers() + (response if response else b'')
		else:
			return b'HTTP/1.1 500 Internal Server Error\r\n\r\n'

		for key, val in self.ret_headers.items():
			x += key + b': ' + val + b'\r\n'
		
		return x + b'\r\n'

	def parse(self):
		# self.info['data'] is the client data.
		# it is inehrited by the client() class and
		# updated in real time.
		if 'data' in self.info and b'\r\n\r\n' in self.info['data']:
			header, self.payload = self.info['data'].split(b'\r\n\r\n') # Copy and split the data so we're not working on live data.
			method, header = header.split(b'\r\n',1)
			for item in header.split(b'\r\n'):
				if b':' in item:
					key, val = item.split(b':',1)
					self.headers[key.strip().lower()] = val.strip()

			method, path, proto = method.split(b' ', 2)
			path_payload = {}
			if b'?' in path:
				path, payload = path.split(b'?', 1)
				for item in payload.split(b'&'):
					if b'=' in item:
						k, v = item.split(b'=',1)
						path_payload[k] = v

			self.headers[b'path'] = path
			self.headers[b'method'] = method
			self.headers[b'path_payload'] = path_payload

			if method in self.methods:
				response = self.methods[method]()
				if type(response) == dict: response = dumps(response)
				if type(response) == str: response = bytes(response, 'UTF-8')
				return self.build_headers() + response if response else self.build_headers()

		return None