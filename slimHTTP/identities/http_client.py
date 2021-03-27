class HTTP_CLIENT_IDENTITY():
	"""
	client identity passed as a reference.
	"""
	def __init__(self, server, socket, address, source_port, on_close=None):
		self.server = server
		self.socket = socket
		self.fileno = socket.fileno()
		self.buffer_size = 8192
		self.address = address
		self.source_port = source_port
		self.closing = False
		self.keep_alive = False

		if on_close: self.on_close = on_close

		self.buffer = b''
		self._buffer = b'' # 

		self.request = HTTP_REQUEST(self)

	def close(self):
		if not self.closing:
			self.on_close(self)
			self.closing = True

	def on_close(self, *args, **kwargs):
		self.closing = True
		self.server.on_close_func(self)

	def clear_cache(self):
		self.buffer = b''
		self._buffer = b''

	def poll(self, timeout=GLOBAL_POLL_TIMEOUT, force_recieve=False):
		"""
		@force_recieve: If the caller knows there's data, we can override
		the polling event and skip straight to data recieving.
		"""
		if force_recieve or list(self.server.poll(timeout, fileno=self.fileno)):
			try:
				d = self.socket.recv(self.buffer_size)
			except: # There's to many errors that can be thrown here for differnet reasons, SSL, OSError, Connection errors etc.
					# They all mean the same thing, things broke and the client couldn't deliver data accordingly so eject.
				d = ''

			if len(d) == 0:
				self.on_close(self)
				return None

			self.buffer += d
			self._buffer = self.buffer
			yield (Events.CLIENT_DATA, len(self.buffer))

	def send(self, data):
		return self.socket.send(data)

	def build_request(self):
		try:
			yield (Events.CLIENT_REQUEST, self.request)
		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			self.server.log(f'Fatal error in HTTP_REQUEST from {self}, {fname}@{exc_tb.tb_lineno}: {e}')
			self.server.log(traceback.format_exc())

	def has_data(self):
		if self.closing:
			return False
		if len(self.buffer):
			return True
		if type(self.request) == HTTP_PROXY_REQUEST and self.request.connected:
			return True
		return False

	def __repr__(self):
		return f'<slimhttpd.HTTP_CLIENT_IDENTITY @ {self.address}:{self.source_port}.{self.fileno}>'