workers = 4  # Adjust the number of worker processes as needed
bind = '0.0.0.0:8000'  # Specify the host and port for your application
worker_class = 'gevent'
worker_connections = 1000
timeout = 60
