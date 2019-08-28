# Using the library: https://github.com/Torxed/spiderWeb

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
from spiderWeb import spiderWeb # https://github.com/Torxed/spiderWeb

class data_parser():
	def parse(self, client, data, headers, fileno, addr, *args, **kwargs):
		print(client, 'sent', data)
		client.send({"type": "json", "data": "test data"})

		# By not returning anything, we'll keep the session alive.

websocket = spiderWeb.upgrader({'default' : data_parser()})
http = slimhttpd.http_serve(upgrades={b'websocket' : websocket})

while 1:
	client = http.accept()

	for fileno, event in http.poll().items():
		if fileno in http.sockets: # If not, it's a main-socket-accept and that will occur next loop
			client = http.sockets[fileno]
			if client.recv():
				resposne = client.parse()
				if resposne:
					try:
						client.send(resposne)
					except BrokenPipeError:
						pass
					client.close()