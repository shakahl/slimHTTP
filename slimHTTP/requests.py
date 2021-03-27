class HTTP_PROXY_REQUEST():
	"""
	Tunnels any data transparently with both initial data and future data.
	Unless one of the ends of the created connection disconnects, this tunnel
	will stay on forever and server both ends.

	It inherits a lot of the properties from :class:`~slimHTTP.HTTP_REQUEST` in order
	to remember which session it belongs to if asked.
	"""
	def __init__(self, CLIENT_IDENTITY, ORIGINAL_REQUEST):
		CLIENT_IDENTITY.server.log(f"Initating a two-way proxy connection between {CLIENT_IDENTITY} and {CLIENT_IDENTITY.server.config['vhosts'][ORIGINAL_REQUEST.vhost]['proxy']}", level=logging.DEBUG)
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self.ORIGINAL_REQUEST = ORIGINAL_REQUEST
		self.config = self.CLIENT_IDENTITY.server.config
		self.vhost = self.ORIGINAL_REQUEST.vhost
		self.poller = epoll()
		self.proxy_sock = None
		self.connected = False

	def __repr__(self, *args, **kwargs):
		if self.proxy_sock:
			proxy_repr = self.proxy_sock
		else:
			proxy_repr = self.config['vhosts'][self.vhost]['proxy']
		return f"<HTTP_PROXY_REQUEST client={self.CLIENT_IDENTITY} vhost={self.vhost}, proxy={proxy_repr}>"

	def connect(self):
		self.proxy_sock = socket()
		self.proxy_sock.settimeout(0.02)
		proxy, proxy_port = self.config['vhosts'][self.vhost]['proxy'].split(':',1)
		try:
			self.proxy_sock.connect((proxy, int(proxy_port)))
			self.CLIENT_IDENTITY.server.log(f'Connected to proxy on {self}', level=logging.DEBUG)
		except:
			# We timed out, or the proxy was to slow to respond.
			self.CLIENT_IDENTITY.server.log(f'Was unable to connect to proxy {self}.', level=logging.ERROR)
			self.proxy_sock = None
			self.connected = False
			self.CLIENT_IDENTITY.server.sockets[self.CLIENT_IDENTITY.fileno].keep_alive = False
			return None
		
		self.proxy_sock.settimeout(None)
		if 'ssl' in self.config['vhosts'][self.vhost] and self.config['vhosts'][self.vhost]['ssl']:
			context = ssl.create_default_context()
			self.proxy_sock = context.wrap_socket(self.proxy_sock, server_hostname=proxy)
			self.CLIENT_IDENTITY.server.log(f'Proxy connection has been wrapped in SSL: {self}')

		# Force the connection to an open state,
		# and we'll determine the sockets future by the state of the two ends of this proxy tunnel.
		self.CLIENT_IDENTITY.server.sockets[self.CLIENT_IDENTITY.fileno].keep_alive = True
		self.poller.register(self.proxy_sock.fileno(), EPOLLIN)

		self.connected = True
		self.disconnected = False

		return True

	def close(self):
		self.CLIENT_IDENTITY.server.log(f'Proxy session closing for {self}.', level=logging.ERROR)
		self.poller.unregister(self.proxy_sock.fileno())
		self.proxy_sock.close()
		self.CLIENT_IDENTITY.server.sockets[self.CLIENT_IDENTITY.fileno].keep_alive = False
		self.disconnected = True

	def parse(self):
		print(self)
		if not self.connected and (status := self.connect()) is not True:
			if status is not None:
				return status

		if not self.connected:
			return None

		if self.CLIENT_IDENTITY._buffer:
			self.CLIENT_IDENTITY.server.log(f'Sending buffer "{id(self.CLIENT_IDENTITY._buffer), self.CLIENT_IDENTITY._buffer[:20]}" to proxy {self}', level=logging.DEBUG)
			try:
				self.proxy_sock.send(self.CLIENT_IDENTITY._buffer)
			except BrokenPipeError as err:
				self.CLIENT_IDENTITY.server.log(f'Calling close() on {self}.', level=logging.ERROR)
				self.close()
				return

			self.CLIENT_IDENTITY.server.log(f'Clearing buffer "{id(self.CLIENT_IDENTITY._buffer), self.CLIENT_IDENTITY._buffer[:20]}" of {self.CLIENT_IDENTITY}', level=logging.DEBUG)
			self.CLIENT_IDENTITY.clear_cache() # Once we've sent the buffer, clear it in case new data comes in

		#if type(self.CLIENT_IDENTITY.server) == HTTP_SERVER and self.CLIENT_IDENTITY.server.is_debuggable(self.ORIGINAL_REQUEST.url):
		#	self.CLIENT_IDENTITY.server.log(f'Forwarded request {self.ORIGINAL_REQUEST} over a insecure connection: {self}')

		#self.CLIENT_IDENTITY.server.log(f'Gathering data from proxy endpoint on {self}', level=logging.DEBUG)
		proxy_buffer = b''
		for socket_fileno, event_type in self.poller.poll(0.02):
			tmp = self.proxy_sock.recv(8192)
			if len(tmp) <= 0:
				self.close()
				break
			proxy_buffer += tmp


		#self.poller.unregister(self.proxy_sock.fileno())
		#self.proxy_sock.close()

		if proxy_buffer:
			if b'HTTP/1.1 200' in proxy_buffer:
				self.CLIENT_IDENTITY.server.log(f'Data "{proxy_buffer[:50]}" recieved, forwarding back to {self.CLIENT_IDENTITY}', level=logging.DEBUG)
			yield (Events.CLIENT_RESPONSE_PROXY_DATA, proxy_buffer)
		
		yield (Events.PROXY_EMPTY_RESPONSE, None)


class HTTP_REQUEST():
	"""
	General request formatter passed as an object throughout the event stack.
	"""
	def __init__(self, CLIENT_IDENTITY):
		""" A dummy parser that will return 200 OK on everything. """
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self._headers = {}
		self._method = None
		self._payload = b''
		self.vhost = None
		self.ret_code = 200 # Default return code.
		self.ret_code_mapper = {200 : b'HTTP/1.1 200 OK\r\n',
								206 : b'HTTP/1.1 206 Partial Content\r\n',
								302 : b'HTTP/1.1 302 Found\r\n',
								404 : b'HTTP/1.1 404 Not Found\r\n',
								418 : b'HTTP/1.0 I\'m a teapot\r\n'}
		self.response_headers = {}
		self.session_storage = {}
		self.web_root = self.CLIENT_IDENTITY.server.config['web_root']

	def __repr__(self):
		return f"<HTTP_REQUEST {self.method} {self.url[:50]}; vhost={self.vhost}>"

	@property
	def data(self):
		if b'content-type' in self._headers:
			if self._headers[b'content-type'] == b'application/json':
				return json.loads(self.payload.decode('UTF-8'))
		return self.payload

	@property
	def headers(self):
		return self._headers # TODO: Decode with UTF8_DICT()

	@property
	def method(self):
		return self._headers[b'METHOD'].decode('UTF-8')

	@property
	def query(self):
		return UTF8_DICT(self._headers[b'URI_QUERY'])

	@property
	def path_params(self):
		return self.query()

	@property
	def url(self):
		try:
			return self._headers[b'URL'].decode('UTF-8')
		except:
			return self._headers[b'URL']

	@property
	def payload(self):
		return self._payload

	@property
	def path(self):
		class path_storage:
			def __init__(self, request):
				self.query = request.query()
				self.params = self.query

		return path_storage(self)
	
	def build_request_headers(self, data):
		## Parse the headers
		if b'\r\n' in data:
			METHOD, header = data.split(b'\r\n',1)
			for item in header.split(b'\r\n'):
				if b':' in item:
					key, val = item.split(b':',1)
					self._headers[key.strip().lower()] = val.strip()
		else:
			METHOD, self._headers = data, {}

		if len(METHOD) > 1024 or METHOD[:1024].count(b' ') < 2 :
			raise InvalidFrame(f"An invalid method was given: {METHOD[:100]}")

		METHOD, URL, proto = METHOD.split(b' ', 2)
		URI_QUERY = {}
		if b'?' in URL:
			URL, QUERIES = URL.split(b'?', 1)
			for item in QUERIES.split(b'&'):
				if b'=' in item:
					k, v = item.split(b'=',1)
					URI_QUERY[k.lower()] = v

		try:
			self._headers[b'URL'] = URL.decode('UTF-8') #TODO: Remove decode and keep the original, use self.url instead, use @property instead.
		except UnicodeDecodeError:
			raise InvalidFrame(f"An invalid URL was given: {URL[:100]}")
		self._headers[b'METHOD'] = METHOD
		self._headers[b'URI_QUERY'] = URI_QUERY

	def locate_index_file(self, index_files, return_any=True):
		if type(index_files) == str:
			if isfile(self.web_root + self._headers[b'URL'] + index_files):
				return index_files
			if return_any:
				return index_files
		elif type(index_files) in (list, tuple):
			for file in index_files:
				if isfile(self.web_root + self._headers[b'URL'] + file):
					if not return_any:
						return file
					break
			if return_any:
				return file

	def build_headers(self, additional_headers={}):
		x = b''
		if self.ret_code in self.ret_code_mapper:
			x += self.ret_code_mapper[self.ret_code]# + self.build_headers() + (response if response else b'')
		else:
			return b'HTTP/1.1 500 Internal Server Error\r\n\r\n'

		for key, val in {**self.response_headers, **additional_headers}.items():
			if type(key) != bytes: key = bytes(key, 'UTF-8')
			if type(val) != bytes: val = bytes(val, 'UTF-8')
			x += key + b': ' + val + b'\r\n'
		
		return x + b'\r\n'

	def check_partial_routes(self, vhost, url):
		partial_route_handlers = []
		for route in self.CLIENT_IDENTITY.server.routes[vhost]:
			if route in url[:len(route)]:
				partial_route_handlers.append(self.CLIENT_IDENTITY.server.routes[vhost][route])

		if len(partial_route_handlers) == 1:
			return partial_route_handlers[0]
		elif len(partial_route_handlers) == 0:
			return None

		raise KeyError(f"Multiple route handlers registered for {url}: {partial_route_handlers}")

	def parse(self):
		"""
		Split the HTTP data into headers and body.
		"""
		if b'\r\n\r\n' in self.CLIENT_IDENTITY.buffer:
			header, remainder = self.CLIENT_IDENTITY.buffer.split(b'\r\n\r\n', 1) # Copy and split the data so we're not working on live data.
#           self.CLIENT_IDENTITY.server.log(f'Request from {self.CLIENT_IDENTITY} being parsed: {header[:2048]} ({remainder[:2048]})')
			self._payload = b''

			try:
				self.build_request_headers(header)
			except InvalidFrame as e:
				print('Error:', e)
				return (Events.INVALID_DATA, e)

			if self._headers[b'METHOD'] in (b'POST', b'PUT'):
				if b'content-length' in self._headers:
					content_length = int(self._headers[b'content-length'].decode('UTF-8'))
					self._payload = remainder[:content_length]

					if len(self._payload) < content_length:
						return (Events.CLIENT_DATA_FRAGMENTED, self)

					self.CLIENT_IDENTITY.buffer = remainder[content_length:] # Add any extended data outside of Content-Length back to the buffer
				else:
					return (Events.NOT_YET_IMPLEMENTED, NotYetImplemented('POST|PUT without Content-Length isn\'t supported yet.'))

			_config = self.CLIENT_IDENTITY.server.config
			if b'host' in self._headers and 'vhosts' in _config and self._headers[b'host'].decode('UTF-8') in _config['vhosts']:
				self.vhost = self._headers[b'host'].decode('UTF-8')
				if 'web_root' in _config['vhosts'][self.vhost]:
					self.web_root = _config['vhosts'][self.vhost]['web_root']

			# Check for @app.route definitions (self.routes in the server object).
			if self.vhost in self.CLIENT_IDENTITY.server.routes and self._headers[b'URL'] in self.CLIENT_IDENTITY.server.routes[self.vhost]:
				yield (Events.CLIENT_URL_ROUTED, self.CLIENT_IDENTITY.server.routes[self.vhost][self._headers[b'URL']].parser(self))
			elif self.vhost in self.CLIENT_IDENTITY.server.routes and (route_handler := self.check_partial_routes(self.vhost, self._headers[b'URL'])):
				yield (Events.CLIENT_URL_ROUTED, route_handler.parser(self))

			# Check vhost specifics:
			if self.vhost:
				instance_config = _config['vhosts'][self.vhost]
			else:
				instance_config = _config

			if 'proxy' in instance_config:
				new_request = HTTP_PROXY_REQUEST(self.CLIENT_IDENTITY, self)
				self.CLIENT_IDENTITY.server.log(f"Swapping HTTP_REQUEST {self.CLIENT_IDENTITY.request} for a more permanent {new_request}", level=logging.DEBUG)
				self.CLIENT_IDENTITY.request = new_request
				for initial_proxy_event, initial_proxy_data in self.CLIENT_IDENTITY.request.parse():
					yield initial_proxy_event, initial_proxy_data

				if not self.CLIENT_IDENTITY.request.connected:
					return self.CLIENT_IDENTITY.close()
				
				return
			elif 'module' in instance_config:
				try:
					loaded_module = Imported(instance_config['module'])
					self.CLIENT_IDENTITY.server.log(f'Routing {self.CLIENT_IDENTITY} to {loaded_module} @ {self.vhost}"')

					with loaded_module as module:
						# Double-check so that the imported module didn't inject something
						# into the route options for the specific vhost.
						if self.vhost in self.CLIENT_IDENTITY.server.routes and self._headers[b'URL'] in self.CLIENT_IDENTITY.server.routes[self.vhost]:
							yield (Events.CLIENT_URL_ROUTED, self.CLIENT_IDENTITY.server.routes[self.vhost][self._headers[b'URL']].parser(self))
						elif hasattr(module, 'on_request'):
							yield (Events.CLIENT_RESPONSE_DATA, module.on_request(self))
				except ModuleError as e:
					print(e.message)
				finally:
					return self.CLIENT_IDENTITY.close()

			# Find suitable upgrades if any
			elif {b'upgrade', b'connection'}.issubset(set(self._headers)) and b'upgrade' in self._headers[b'connection'].lower():
				requested_upgrade_method = self._headers[b'upgrade'].lower()
				self.CLIENT_IDENTITY.server.log(f'Looking up upgrader {requested_upgrade_method} for {self.CLIENT_IDENTITY}')
				new_identity = self.CLIENT_IDENTITY.server.on_upgrade_func(self)
				if new_identity:
					self.CLIENT_IDENTITY.server.log(f'{self.CLIENT_IDENTITY} has been upgraded to {new_identity}')
					self.CLIENT_IDENTITY.server.sockets[self.CLIENT_IDENTITY.fileno] = new_identity
					yield (Events.CLIENT_UPGRADED, new_identity)
					return
				else:
					self.CLIENT_IDENTITY.server.log(f'Could not upgrade {self.CLIENT_IDENTITY} using {self.CLIENT_IDENTITY.server.on_upgrade_func}', level=logging.ERROR)
					yield (Events.CLIENT_UPGRADE_ISSUE, UpgradeIssue(f'Could not upgrade client {self.CLIENT_IDENTITY} with desired upgrader: {requested_upgrade_method}'))
					return

			# Lastly, handle the request as one of the builtins (POST, GET)
			if len(self._headers[b'URL']) and (response := self.CLIENT_IDENTITY.server.REQUESTED_METHOD(self)):
				self.CLIENT_IDENTITY.server.log(f'{self.CLIENT_IDENTITY} sent a "{self._headers[b"METHOD"].decode("UTF-8")}" request to path "[{self.web_root}/]{self._headers[b"URL"]} @ {self.vhost}"')

				for event, event_data in response:
					yield event, event_data