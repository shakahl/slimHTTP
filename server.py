import slimhttpd

http = slimhttpd.host(slimhttpd.HTTP, config={})

@http.configuration
def config(instance):
	return {
		'web_root' : './',
		'index' : 'index.html'
	}

@http.method_GET
def get(request=None, headers={}, payload={}, root='./', *args, **kwargs):
	print(request)

@http.allow({'127.0.0.1/8'})
def on_accept(clients):
	print('New clients:', clients)

@http.on_close
def close(client_identity):
	print('Client closes:', client_identity)
	http.unregister(client_identity)
	client_identity.close()

while 1:
	for event, entity in http.poll():
		print(event, entity)