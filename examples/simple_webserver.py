from json import dumps, loads
# Import slimHTTP after configuration has been set up
# to avoid default configuration being loaded (TODO to fix this)

__builtins__.__dict__['LEVEL'] = 5   # Logging level
__builtins__.__dict__['config'] = {  # slimHTTP configuration parameters
	'slimhttp' : {
		'web_root' : './',
		'index' : 'index.html',
		'vhosts' : {
			'messages2.me' : {
				'web_root' : './messages_to_me_webroot',
				'index' : 'index.html'
			}
		}
	}
}

def get(request=None, headers={}, payload={}, root='./', *args, **kwargs):
	if headers[b'path'] == f'/homepage.html':
		with open('./homepage.html', 'rb') as payload:
			data = payload.read()

		request.ret_headers = {}
		request.ret_headers[b'Content-Length'] = bytes(str(len(data)), 'UTF-8')
		request.ret_headers[b'Server'] = b'slimHTTP/1.0'
		return data

def post(request=None, headers={}, payload={}, root='./', *args, **kwargs):
	if headers[b'path'] == '/api/hello':
		ret_payload = dumps({"commands" : ["hello", "quit"]})

		request.ret_headers = {}
		request.ret_headers[b'Content-Length'] = bytes(str(len(ret_payload)), 'UTF-8')
		request.ret_headers[b'Content-Type'] = b'application/json; charset=utf-8'
		request.ret_headers[b'Server'] = b'slimHTTP/1.0'
		return ret_payload

	elif headers[b'path'] == f'/api/quit':
		request.ret_code = 204
		request.ret_data[204] = b'HTTP/1.1 204 No Content\r\n'

		request.ret_headers[b'Content-Length'] = b'0'
		request.ret_headers[b'Server'] = b'slimHTTP/1.0'
		return b''

from slimHTTP import slimhttpd
from slimHTTP import slimhttpd
http = slimhttpd.http_serve(upgrades={b'websocket': websocket})
https = slimhttpd.https_serve(upgrades={b'websocket': websocket}, cert='cert.pem', key='key.pem')

sockets = {}

while 1:
	# Accept new clients
	for handler in [http, https]:
		client = handler.accept()
		if client:
			# If we cant a truly state-less connection:
			client.keep_alive = True

		# Iterate over already accepted clients
		for fileno, event in handler.poll().items():
			if fileno in handler.sockets:
				client = handler.sockets[fileno]
				if client.recv():
					response = client.parse()
					if response:
						try:
							client.send(response)
							client.data = b'' # Flush client data before next recieve, useful for keep-alive sessions
						except BrokenPipeError:
							pass
						if not client.keep_alive:
							client.close()
