import slimhttpd

http = slimhttpd.host(slimhttpd.HTTP)

@http.configuration
def config(instance):
	return {
		'web_root' : './',
		'index' : 'index.html'
	}

while 1:
	for event, *event_data in http.poll():
		pass