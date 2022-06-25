# Fullcone Breaker

This is an NAT traversal tool for fullcone NAT only, allowing TCP traversal.

## Prerequision

Fullcone NAT is required. If your ISP uses CGN, it's very likely that you have fullcone NAT.

Additionally, any NAT box between your computer and internet need to be fullcone, or you can set DMZ to your computer.

## Usage

Server:
```
./server
    -l [<listen ip>]:<port>   API exposing host, the API will listen as http
    [-u <username>]           Set username to secure the API, optional
    [-p <password>]           Set password to secure the API, optional
```

Client:
```
./client -c <path to config file>
```

Client Config File:
```
[common]
server = http://<user>:<pass>@<server host>:<server port> # Server API address
heartbeat_interval = 15           # Heartbeat frequency 

[http_service]         # Name of exposing service
type = http            # Type of service, support tcp/http/https
local_ip = 127.0.0.1   # LAN IP of the service
local_port = 5000      # LAN Port of the service
remote_ip = 0.0.0.0    # [Optional] Listening IP on your server, optional, default to all IP
remote_port = 5000     # Listening Port 
http_cache_time = 0    # [Optional] Cache time of HTTP, will also control the HTTP Redirect cache.
http_altsvc = true     # [Optional] Use AltSvc instead of redirection
http_altsvc_nip_domain = ip.example.com # [Optional] Set AltSvc domain

[https_service]
type = https
local_ip = 127.0.0.1   # LAN IP of the service
local_port = 5001      # LAN Port of the service
remote_ip = 0.0.0.0    # [Optional] Listening IP on your server, optional, default to all IP
remote_port = 5001     # Listening Port on server
http_backend=https     # [Optional] HTTP Backend (http/https/proxy), default to http
https_crt = /certs/example.com.crt # TLS Certificate
https_key = /certs/example.com.key # TLS Private Key

[http_proxy]
type = http
bind_ip = 0.0.0.0      # [Optional] Binding IP on your computer, optional, default to all IP
bind_port = 5012       # [Optional] Binding port on your computer, optional, default ramdom port
remote_port = 5002     # Listening Port
http_username=proxy    # [Optional] HTTP Basic Auth Username
http_password=password # [Optional] HTTP Basic Auth Password
http_backend=proxy

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 2200
```