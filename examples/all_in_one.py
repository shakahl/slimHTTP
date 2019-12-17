import signal, json
from select import epoll, EPOLLIN, EPOLLHUP

def sig_handler(signal, frame):
	http.close()
	https.close()
	exit(0)
signal.signal(signal.SIGINT, sig_handler)

## Set up logging early on:
import logging
from systemd.journal import JournalHandler

# Custom adapter to pre-pend the 'origin' key.
# TODO: Should probably use filters: https://docs.python.org/3/howto/logging-cookbook.html#using-filters-to-impart-contextual-information
class CustomAdapter(logging.LoggerAdapter):
	def process(self, msg, kwargs):
		return '[{}] {}'.format(self.extra['origin'], msg), kwargs

logger = logging.getLogger() # __name__
journald_handler = JournalHandler()
journald_handler.setFormatter(logging.Formatter('[{levelname}] {message}', style='{'))
logger.addHandler(journald_handler)
logger.setLevel(logging.DEBUG)

class LOG_LEVELS:
	CRITICAL = 1
	ERROR = 2
	WARNING = 3
	INFO = 4
	DEBUG = 5

def _log(*msg, origin='UNKNOWN', level=5, **kwargs):
	if level <= LOG_LEVEL:
		msg = [item.decode('UTF-8', errors='backslashreplace') if type(item) == bytes else item for item in msg]
		msg = [str(item) if type(item) != str else item for item in msg]
		log_adapter = CustomAdapter(logger, {'origin': origin})
		if level <= 1:
			log_adapter.critical(' '.join(msg))
		elif level <= 2:
			log_adapter.error(' '.join(msg))
		elif level <= 3:
			log_adapter.warning(' '.join(msg))
		elif level <= 4:
			log_adapter.info(' '.join(msg))
		else:
			log_adapter.debug(' '.join(msg))

class _safedict(dict):
	def __init__(self, *args, **kwargs):
		args = list(args)
		self.debug = False
		for index, obj in enumerate(args):
			if type(obj) == dict:
				m = safedict()
				for key, val in obj.items():
					if type(val) == dict:
						val = safedict(val)
					m[key] = val

				args[index] = m

		super(safedict, self).__init__(*args, **kwargs)

	def __getitem__(self, key):
		if not key in self:
			self[key] = safedict()

		val = dict.__getitem__(self, key)
		return val

	def __setitem__(self, key, val):
		if type(val) == dict:
			val = safedict(val)
		dict.__setitem__(self, key, val)

	def dump(self, *args, **kwargs):
		copy = safedict()
		for key in self.keys():
			val = self[key]
			if type(key) == bytes and b'*' in key: continue
			elif type(key) == str and '*' in key: continue
			elif type(val) == dict or type(val) == safedict:
				val = val.dump()
				copy[key] = val
			else:
				copy[key] = val
		return copy

	def copy(self, *args, **kwargs):
		return super(safedict, self).copy(*args, **kwargs)

## Set up globals that can be used in this project (including sub modules)
__builtins__.__dict__['LOG_LEVEL'] = LOG_LEVELS.INFO
__builtins__.__dict__['log'] = _log
__builtins__.__dict__['safedict'] = _safedict
__builtins__.__dict__['config'] = safedict({
	'slimhttp': {
		'web_root': abspath('./web_content'),
		'index': 'index.html',
		'vhosts': {
			'obtain.life': {
				'web_root': abspath('./web_content'),
				'index': 'index.html'
			}
		}
	}
})

if isfile('datstore.json'):
	with open('datstore.json', 'r') as fh:
		log('Loading sample datastore from {{datstore.json}}', origin='STARTUP', level=5)
		__builtins__.__dict__['datastore'] = safedict(json.load(fh))

		#datastore = dict_to_safedict(datastore)
else:
	log(f'Starting with a clean database (reason: couldn\'t find {{datastore.json}})', origin='STARTUP', level=5)
	__builtins__.__dict__['datastore'] = safedict()


## Import sub-modules after configuration setup.
## (This so it doesn't break the logging..)
from dependencies.slimHTTP import slimhttpd
from dependencies.spiderWeb import spiderWeb
# Don't forget to generate a key-pair: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

class pre_parser():
	def parse(self, client, data, headers, fileno, addr, *args, **kwargs):
		yield {'status' : 'successful'}

websocket = spiderWeb.upgrader({'default': pre_parser()})
http = slimhttpd.http_serve(upgrades={b'websocket': websocket})
https = slimhttpd.https_serve(upgrades={b'websocket': websocket}, cert='cert.pem', key='key.pem')

while 1:
	for handler in [http, https]:
		client = handler.accept()

		#for fileno, client in handler.sockets.items():
		for fileno, event in handler.poll().items():
			if fileno in handler.sockets:  # If not, it's a main-socket-accept and that will occur next loop
				client = handler.sockets[fileno]
				if client.recv():
					response = client.parse()
					if response:
						try:
							client.send(response)
						except BrokenPipeError:
							pass
						client.close()