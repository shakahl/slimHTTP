import os

__builtins__.__dict__['LEVEL'] = 5 # TODO: <- Remove/rename this.
__builtins__.__dict__['sockets'] = {
}
__builtins__.__dict__['config'] = {
	'slimhttp' : {
		'web_root' : './web_content',
		'index' : 'index.html',
		'vhosts' : {
			'messages2.me' : {
				'web_root' : './web_content',
				'index' : 'index.html'
			}
		}
	}
}

## Import sub-modules after configuration setup.
from slimHTTP import slimhttpd

if not os.path.isfile('server.crt') or not os.path.isfile('server.key'):
	# Returns None if it couldn't generate a key/cert pair.
	if not slimhttpd.generate_key_and_cert('server.key', cert_file='server.crt'):
		raise OSError('Missing python-openssl.\n Run: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365')
		
https = slimhttpd.https_serve(cert='server.crt', key='server.key')

while 1:
	client = https.accept()

	for fileno, event in https.poll().items():
		if fileno in https.sockets: # If not, it's a main-socket-accept and that will occur next loop
			sockets[fileno] = https.sockets[fileno]
			client = https.sockets[fileno]
			if client.recv():
				resposne = client.parse()
				if resposne:
					try:
						client.send(resposne)
					except BrokenPipeError:
						pass
					client.close()
