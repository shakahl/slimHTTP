# Make sure you generate a cert.pem and a key.pem:
# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

__builtins__.__dict__['LEVEL'] = 5
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
from spiderWeb import spiderWeb

https = slimhttpd.https_serve(cert='cert.pem', key='key.pem')

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