from socket import *
from ssl import wrap_socket
from select import epoll, EPOLLIN, EPOLLOUT, EPOLLHUP

from time import time, sleep
logs = {}
def log(*args, **kwargs):
	if not 'level' in kwargs:
		kwargs['level'] = 0 # info, 1 = warn, 2 = error, 3+ temporary/custom errors.

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
		try:
			self.parent.close(fileno=self.socket.fileno())
		except:
			return None
		return True

	def respond(self, d):
		if type(d) != bytes:
			d = bytes(d, 'UTF-8')

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
		events = self.poll()
		if self.main_so_id in events:
			ns, na = self.sock.accept()
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
				self.sockets[fileno].close()
				return True
			except:
				return None
		else:
			for fileno in self.sockets:
				try:
					self.pollobj.unregister(fileno)
					self.sockets[fileno].close()
				except:
					pass
			self.pollobj.unregister(self.main_so_id)
			self.sock.close()

class https_serve():
	def __init__(self):
		pass

class http_request():
	def __init__(self, client_info):
		""" A dummy parser that will return 200 OK on everything. """
		self.info = client_info
		self.headers = {}
		self.payload = {}

	def parse(self):
		# self.info['data'] is the client data.
		# it is inehrited by the client() class and
		# updated in real time.
		if b'\r\n\r\n' self.info in self.info['data']:
			header, data = self.info['data'].split(b'\r\n\r\n') # Copy and split the data so we're not working on live data.
			for item in headers.split(b'\r\n'):
				if b':' in item:
					key, val = item.split(b':')
					self.headers[key.strip().lower()] = val.strip()

			print(self.headers)
		else:
			return None

		return b'HTTP/1.1 200 OK\r\n\r\n'

# x = http_serve()
# 
# clients = {}
# 
# client = x.accept()
# # if client in clients: close()
# clients[client.id()] = {'handle' : client, 'parser' : http_request(client.info)}
# 
# data = None
# while data is None:
# 	data = client.recv(8192)
# 	if data:
# 		client.respond( clients[client.id()]['parser'].parse() )
# 
# 		# TODO: Should be timed so it doesn't live to long.
# 		# (we're still "safe", the kernel will drop the connection
# 		#  after a while if no data was sent. And if the user tries
# 		#  to resend anything, we will drop the old conenction.
# 		#  still, we have a max fileno() to allocate, so help the kernel!)
# 		client.close()
