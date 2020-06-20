import slimhttpd
import spiderWeb

http = slimhttpd.host(slimhttpd.HTTP)
websocket = spiderWeb.WebSocket()

@http.configuration
def config(instance):
	return {
		'web_root' : './',
		'index' : 'index.html'
	}

@http.on_close
def close(client_identity):
	http.unregister(client_identity)
	client_identity.close()

@http.route('/hellowWorld.html')
def api_helloWorld(request):
 	return slimhttpd.HTTP_RESPONSE(headers={'Content-Type' : 'text/html'},
 									payload=b'<html><body>Test</body></html>')

@websocket.route('/auth/login')
def auth_handler(request):
	print('Auth:', request)

@http.on_upgrade
def upgrade(request):
	print('Upgrading to WS_CLIENT_IDENTITY')
	new_identity = websocket.WS_CLIENT_IDENTITY(request)
	new_identity.upgrade(request)
	return new_identity

while 1:
	for event, *event_data in http.poll():
		# print(event, event_data)
		pass