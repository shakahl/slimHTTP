import ssl
from socket import *
from select import epoll, EPOLLIN, EPOLLOUT, EPOLLHUP
from os.path import isfile, abspath
from mimetypes import guess_type # TODO: issue consern, doesn't handle bytes,
#								   requires us to decode the string before guessing type.
from json import dumps
from time import time, sleep

#ifdef !log (Yea I know, this should be a 'from main import log' or at least a try/catch)
if not 'log' in __builtins__ or ('__dict__' in __builtins__ and not 'log' in __builtins__.__dict__):
	def _log(*args, **kwargs):
		if not 'level' in kwargs or kwargs['level'] <= LEVEL:
			## TODO: Try journald first, print as backup
			print(args, kwargs)
			#with open('debug.log', 'a') as output:
			#	output.write('{}, {}\n'.format(args, kwargs))
	try:
		__builtins__.__dict__['log'] = _log
	except:
		__builtins__['log'] = _log

#ifdef
if not 'config' in __builtins__ or ('__dict__' in __builtins__ and not 'config' in __builtins__.__dict__):
	config = {}

#ifdef
if not 'slimhttp' in config:
	config['slimhttp'] = {
		'web_root' : '/srv/http',
		'index' : 'index.html',
		'vhosts' : {
			'domain.me' : {
				'web_root' : '/srv/http/domain.me',
				'index' : 'index.html'
			}
		}
	}

def as_complex(o):
	if type(o) == bytes:
		return o.decode('UTF-8')
	return o

def drop_privileges():
	return True

class http_cliententity():
	def __init__(self, parent, sock, addr=None):
		self.info = {'addr' : addr}

		self.data = b''

		self.upgraded = False
		self.keep_alive = True
		self.parent = parent
		self.socket = sock
		self.id = self.info['addr'][0]

	def __repr__(self):
		return 'client[{}:{}]'.format(*self.info['addr'])

	def recv(self, buffert=8192):
		if self.parent.poll(fileno=self.socket.fileno()):
			d = self.socket.recv(buffert)
			if len(d) == 0:
				self.close()
				return None
			self.data += d
			return len(self.data)
		return None

	#def id(self):
	#	return self.info['addr'][0] 

	def close(self):
		self.socket.close()
		return True

	def send(self, d):
		self.respond(d)

	def respond(self, d):
		if d is None: d = b'HTTP/1.1 200 OK\r\n\r\n'

		if type(d) != bytes:
			d = bytes(d, 'UTF-8')

		#print('>', d)
		self.socket.send(d)
		return True

	def parse(self):
		return http_request(self).parse()


class http_serve():
	def __init__(self, modules={}, methods={}, upgrades={}, port=80):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.bind(('', port))

		self.pollobj = epoll()
		self.sockets = {}
		self.modules = modules
		self.methods = methods
		self.upgrades = upgrades

		while drop_privileges() is None:
			log('slimHTTP', 'http_serve', 'Waiting for privileges to drop.', once=True, level=1)

		self.sock.listen(10)
		self.main_so_id = self.sock.fileno()
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

	def accept(self, client_trap=http_cliententity):
		if self.poll(0.025, fileno=self.main_so_id):
			ns, na = self.sock.accept()
			log('slimHTTP', 'http_server', 'Accepting new client: {addr}'.format(**{'addr' : na[0]}), level=3)
			ns_fileno = ns.fileno()
			if ns_fileno in self.sockets:
				self.sockets[ns_fileno].close()
				del self.sockets[ns_fileno]

			self.sockets[ns_fileno] = http_cliententity(self, ns, na)
			self.pollobj.register(ns_fileno, EPOLLIN)
			return self.sockets[ns_fileno]
		return None

	def poll(self, timeout=0.025, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self, fileno=None):
		if fileno:
			try:
				log('slimhttp', 'close', f'closing fileno: {fileno}', level=5)
				self.pollobj.unregister(fileno)
			except FileNotFoundError:
				pass # Already unregistered most likely.
			if fileno in self.sockets:
				self.sockets[fileno].close()
			return True
		else:
			for fileno in self.sockets:
				try:
					log('slimhttp', 'close', f'closing fileno: {fileno}', level=5)
					self.pollobj.unregister(fileno)
					self.sockets[fileno].socket.close()
				except:
					pass
			self.pollobj.unregister(self.main_so_id)
			self.sock.close()

class https_serve(http_serve):
	def __init__(self, cert, key, *args, **kwargs):
		super(https_serve, self).__init__(port=443, *args, **kwargs)
		self.pollobj.unregister(self.sock.fileno())

		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(cert, key)
		self.sock = context.wrap_socket(self.sock, server_side=True)
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

def get_file(root, path, *args, **kwargs):
	real_path = abspath('{}/{}'.format(root, path))
	log('slimHTTP', 'get_file', 'Trying to fetch "{}"'.format(real_path), level=4)
	if isfile(real_path):
		with open(real_path, 'rb') as fh:
			data = fh.read()
		
		log('slimHTTP', 'get_file', 'Returning file content:', len(data), level=4)
		return real_path, data

	log('slimHTTP', 'get_file', '404 - Could\'t locate file', level=4)

class http_request():
	def __init__(self, client):
		""" A dummy parser that will return 200 OK on everything. """
		self.client = client
		self.info = client.info
		self.headers = {}
		self.payload = b''
		self.methods = client.parent.methods
		self.ret_code = 200
		self.ret_data = {200 : b'HTTP/1.1 200 OK\r\n',
						 404 : b'HTTP/1.1 404 Not Found\r\n'}
		self.ret_headers = {} # b'Content-Type' : 'plain/text' ?
		log('slimHTTP', 'http_request', 'Setting up a parser for client: {}'.format(client), once=True, level=4)

		if len(self.methods) <= 0:
			log('slimHTTP', 'http_request', 'No methods registered, using defaults.', once=True, level=5)
			self.methods[b'GET'] = self.GET

	def local_file(self, root, path):
		data = get_file(root, path)
		if data:
			path, data = data
			mime = guess_type(path)[0] #TODO: Deviates from bytes pattern. Replace guess_type()
			self.ret_headers[b'Content-Type'] = bytes(mime, 'UTF-8') if mime else b'plain/text'
		else:
			self.ret_code = 404
			data = None
		return data

	def PUT(self):
		return None

	def GET(self, headers={}, payload={}, root='./'):
		return self.local_file(root=root, path=headers[b'path'])

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
		# self.client.data is the client data.
		# it is inehrited by the client() class and
		# updated in real time.
		if b'\r\n\r\n' in self.client.data:
			header, self.payload = self.client.data.split(b'\r\n\r\n') # Copy and split the data so we're not working on live data.
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
						path_payload[k.lower()] = v

			self.headers[b'path'] = path.decode('UTF-8')
			self.headers[b'method'] = method
			self.headers[b'path_payload'] = path_payload

			if self.headers[b'path'] == '/':
				self.headers[b'path'] = config['slimhttp']['index']

				if b'host' in self.headers and 'vhosts' in config['slimhttp'] and self.headers[b'host'].decode('UTF-8') in config['slimhttp']['vhosts']:
					if 'index' in config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]:
						self.headers[b'path'] = config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]['index']

			web_root = config['slimhttp']['web_root']
			if b'host' in self.headers and 'vhosts' in config['slimhttp'] and self.headers[b'host'].decode('UTF-8') in config['slimhttp']['vhosts']:
				if 'web_root' in config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]:
					web_root = config['slimhttp']['vhosts'][self.headers[b'host'].decode('UTF-8')]['web_root']

					#self.headers[b'upgrade'].lower() == b'websocket' and \
			if b'upgrade' in self.headers and b'connection' in self.headers and \
					b'upgrade' in self.headers[b'connection'].lower() and \
					self.headers[b'upgrade'].lower() in self.client.parent.upgrades:
				log('slimHTTP', 'parse', '{} wants to upgrade with {}'.format(self.client, self.headers[b'upgrade']), level=1)
				upgraded = self.client.parent.upgrades[self.headers[b'upgrade'].lower()].upgrade(self.client, self.headers, self.payload)
				if upgraded:
					log('slimHTTP', 'parse', 'Client has been upgraded!', level=5)
					self.client.parent.sockets[self.client.socket.fileno()] = upgraded

			elif method in self.methods:
				log('slimHTTP', 'parse', '{} sent a "{}" request to path "[{}/]{}"'.format(self.client, method.decode('UTF-8'), web_root,self.headers[b'path']), once=True, level=2)
				response = self.methods[method](self.headers, self.payload, root=web_root)
				if type(response) == dict: response = dumps(response)
				if type(response) == str: response = bytes(response, 'UTF-8')
				return self.build_headers() + response if response else self.build_headers()
			else:
				log('slimHTTP', 'parse', 'Can\'t handle {} method.'.format(method), once=True, level=1)
		else:
			log('slimHTTP', 'parse', 'Not enough data yet.', once=True, level=5)

		return None
