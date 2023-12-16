[![Docker](https://github.com/Max-Sum/fcbreak/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Max-Sum/fcbreak/actions/workflows/docker-publish.yml)

[English](https://github.com/Max-Sum/fcbreak/blob/master/README_en.md)

# Fullcone Breaker

专为Fullcone NAT打造的TCP打洞工具。

## 需求

使用之前，必须确认本地网络拥有Fullcone NAT，如果您的运营商部署了CGN，大概率使用的就是Fullcone NAT。

然而，在您的电脑和互联网中间部署的任何NAT设备都需要确保为Fullcone，这些设备包括路由器、路由模式的光猫，通常可以通过设置DMZ来解决。您可能因为防火墙等原因无法正常使用。您可以通过stun检测本地网络是否为fullcone NAT。

此外您还需要一个在公网能访问的服务器，服务器前不能布置任何有SNAT的设备。

## 原理

TCP打洞原理与UDP打洞类似。但Fullcone的大部分设备都不会对流的发起方向作限制。因此可以维持一条对服务器的TCP连接，从而维持流状态。

此外，传统打洞需要客户端部署设备读取暴露的端口。本项目可以使用HTTP转跳的方式完成，无需特别部署客户端。

## 快速部署

### 服务端

```
docker run -n fcbreak --host gzmaxsum/fcbreak-server -l :7000 
```

### 客户端

#### 配置文件

```
[common]
server = http://<服务器地址>:7000

[ssh]  # 暴露TCP服务
type = tcp
local_port = 22
remote_port = 2200

[http] # 暴露http服务
type = http
local_port = 80
remote_port = 8080
```

#### 运行

```
docker run -n fcbreak --host -v /config.ini:<配置文件路径>:ro gzmaxsum/fcbreak-client
```

#### 使用

运行成功访问：`http://<服务器地址>:8080`，会自动转跳到 `http://<公网IP>:<随机端口>`。此时即可直连使用服务。

TCP服务如果连接 `<服务器地址>:2200`则会由服务器中转。您可以访问 `http://<服务器地址>:7000/services`，查看当前所有注册的服务及其对应的端口。

```
{
    "ssh": {
        "name": "ssh",
        "remote_addr": ":2200",
        "exposed_addr": "114.514.19.19:8810",    # 此处为暴露的公网地址
        "scheme": "tcp",
    },
    "http": {
        "name": "http",
        "remote_addr": ":8080",
        "exposed_addr": "114.514.19.19:8222",    # 此处为http暴露的公网地址，即上述转跳到的地址
        "scheme": "http",
    }
}
```

## 进阶功能

### 保护API

API直接暴露在公网且没有密码保护并不安全。通过设置证书可以使用https加密。
服务端：

```
docker run -n fcbreak --host \
    -v /certs:<证书目录>:ro   \
    gzmaxsum/fcbreak-server  \
    -s :7000                 \  # HTTPS 监听 7000 端口
    --cert /certs/public.pem \  # 公钥
    --key  /certs/private.pem\  # 私钥
    -u <用户名> -p <密码>
```

客户端配置文件：

```
[common]
server = https://<用户名>:<密码>@<服务器地址>:7000
# skip_verify = false           # 跳过证书检查，使用自签证书可以使用此项，注意这并不安全。
```

如果使用自签证书，客户端可以挂载公钥以保证安全

```
docker run -n fcbreak --host \
    -v /etc/ssl/certs/ca-certificates.crt:<公钥地址>:ro \
    gzmaxsum/fcbreak-client -c /config.ini:<配置文件路径>:ro [-f]
```

### HTTPS

客户端可以转发https，如果后端为http，还会设置 `X-Forwarded-For`、`X-Real-IP`等头部通知后端真实IP。

#### ACME证书

由于HTTP-01的验证方式不太可行，建议选择DNS-01配置dns注册泛域名证书。

```
[https_http] # 暴露https服务，后端为http
type = https
local_port = 80
remote_port = 8443
http_backend = http
https_crt = <公钥位置>
https_key = <私钥位置>

[https_https] # 暴露https服务，后端为https
type = https
local_port = 443
remote_port = 8444
http_backend = https
https_crt = <公钥位置>
https_key = <私钥位置>
```

### 域名转跳

如果您部署了证书，转跳到IP地址时就会因名称不同而造成证书无效。

此时您可以部署DDNS域名或NIP域名的方式，设置转跳的域名地址。
DDNS和NIP只需设置一个即可。

```
[https_http] # 暴露https服务，后端为http
type = https
local_port = 80
remote_port = 8443
http_backend = http
https_crt = <公钥位置>
https_key = <私钥位置>

http_ddns_domain = ddns.example.com
                       # [可选] DDNS域名，如果设置，则转跳时会跳至该域名而不是IP。DDNS需要另外设置。
http_nip_domain = ip.example.com
                       # [可选] NIP域名，如果设置，则转跳时会跳至123-234-123-23.ip.example.com。
```

#### NIP说明

NIP是一种特殊的域名，它与IP地址一一对应，如 `114-514-19-19.ip.example.com`会解析为 `114.514.19.19`。
这样既可以解决动态IP问题，也可以通过泛域名证书 `*.ip.example.com`来认证。NIP会比DDNS更及时地更新IP。

NIP的服务器需要另外部署，参见[sslip.io](https://sslip.io/)。

### 虚拟服务

每一个HTTP服务都占据一个端口很占用端口空间，可以配置虚拟服务器，共享API的端口。
https、http均可使用。
但如果使用https服务则需要开启https API端口，使用http服务则需要开启http API端口。两种API接口可以同时打开。
Hostname可以在开始或末尾存在一个通配符*，按照 完全匹配 > 开头的通配符 > 结尾的通配符 的顺序匹配。

```
[http] # 暴露http服务
type = http
local_port = 80
#remote_port = 8080   # 配置虚拟服务器时可以不绑定端口
http_hostname = svc.example.com, svc.foobar.com, \*.example.com, foobar.org.\*

[https_http] # 暴露https服务，后端为http
type = https
local_port = 80
remote_port = 8443
http_backend = http
https_crt = <公钥位置>
https_key = <私钥位置>
http_hostname = svc.example.com, svc.foobar.com, \*.example.com, foobar.org.\*
```

另外还需设置 `svc.example.com`和 `svc.foobar.com`指向服务器地址。

完成后可以访问 `http://svc.example.com:<HTTP API端口>`或 `https://svc.foobar.com:<HTTPS API端口>`。

### 服务端部署于代理之后

如果代理支持proxy protocol并能正确设置源IP及源端口，则本服务可以部署于代理之后。
服务器开启proxy protocol：

```
docker run -n fcbreak gzmaxsum/fcbreak-server  \
    -l [<监听IP>]:<端口>  \     # HTTP 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    -s [<监听IP>]:<端口>  \     # HTTPS 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    [--cert <cert file>] \     # [可选]HTTPS 证书公钥文件路径，若使用-s则必须设置
    [--key <key file>]   \     # [可选]HTTPS 私钥文件路径，若使用-s则必须设置
    --proxy-protocol   \     # [可选]使用proxy protcol，仅作为代理服务器后使用
    [-u <username>]      \     # [可选]服务端用户名
    [-p <password>]      \     # [可选]服务端密码
```

### 认证

http/https服务，均可以开启认证

```
[http] # 暴露http服务
type = http
local_port = 80
remote_port = 8080
http_username = <用户名>
http_password = <密码>
```

### HTTP/HTTPS代理

仅暴露http服务有时并不足够，此时可以暴露一个HTTP代理，从而连接到内网。
由于代理可能造成安全隐患，请务必设置认证，且尽量选择https代理。

```
[http_proxy]           # http proxy 类型
type = https           # 设置http或者https
                       # proxy类型无需设置后端地址
remote_port = 5201
http_backend=proxy     # 后端为proxy时对外暴露代理
http_proxy_chain=http://localhost:3128
                       # [可选] 级联代理，将请求转发到下一级代理。可以使用http或socks类型。
http_username=proxy    # [可选] http认证用户名
http_password=password # [可选] http认证密码
https_crt = /certs/example.com.crt # TLS 公钥证书位置，设置为https时必须
https_key = /certs/example.com.key # TLS 私钥证书位置，设置为https时必须
```

代理类型无法进行http转跳，所以需要通过API查询暴露的公网地址。因此http代理还提供了clash订阅、Quantumult X订阅。通过订阅可以自动更新IP地址及端口。

clash订阅：`https://<服务器IP>:5201/clash`

quanx订阅：`https://<服务器IP>:5201/quanx`

您也可以编写脚本访问API来获取直连地址。

### AltSvc

部分浏览器支持 `AltSvc`功能，允许在域名不变的情况下更换后端服务器地址。
此功能通常需要HTTPS。而且并不是任何情况都可以开启，可能造成流量经过服务器中转的情况，请谨慎开启。

```
[https_http]
type = https
local_port = 80
remote_port = 8443
http_backend = http
https_crt = <公钥位置>
https_key = <私钥位置>
http_altsvc = true     # [可选] 使用altsvc代替转跳。
```

### 连接器

连接器支持在linux下访问API获取暴露的服务，并维护iptables规则。从而在本机无感地访问内网服务。

```
sudo ./connector
    -s http[s]://[<user>:<pass>@]<server host>:<server port> # 服务器 API
    [-i <interval>]               # 更新间隔，默认为 300s
```

### 其他更新暴露地址的方式

你可以通过`services_info_path`读取到服务的暴露地址，从而通过其他方式（如其他订阅、协议、API）通知客户端。

客户端设置：
```
[common]
services_info_path = /run/fcbreak/services # 默认为/run/fcbreak/services
```

```
# cat /run/fcbreak/services/<服务名>
{
 "name": "<服务名>",
 "remote_addr": ":1100",
 "exposed_addr": "114.51.4.19:810",
 "scheme": "https",
 "hostnames": [
  "foo.bar"
 ]
}
```

## 详细参数

服务器端:

```
./server
    -l [<监听IP>]:<端口> \       # HTTP 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    -s [<监听IP>]:<端口> \      # HTTPS 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    [--cert <cert file>]\      # [可选]HTTPS 证书公钥文件路径，若使用-s则必须设置
    [--key <key file>]  \      # [可选]HTTPS 私钥文件路径，若使用-s则必须设置
    [--proxy-protocol]  \      # [可选]使用proxy protcol，仅作为代理服务器后使用
    [-u <username>]     \      # [可选]服务端用户名
    [-p <password>]     \      # [可选]服务端密码
```

Docker 服务端：

```
docker run -n fcbreak --host gzmaxsum/fcbreak-server  \
    -l [<监听IP>]:<端口>  \     # HTTP 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    -s [<监听IP>]:<端口>  \     # HTTPS 监听API，用于与客户端通信。-l或-s至少设置一个，可以设置多个
    [--cert <cert file>] \     # [可选]HTTPS 证书公钥文件路径，若使用-s则必须设置
    [--key <key file>]   \     # [可选]HTTPS 私钥文件路径，若使用-s则必须设置
    [--proxy-protocol]   \     # [可选]使用proxy protcol，仅作为代理服务器后使用
    [-u <username>]      \     # [可选]服务端用户名
    [-p <password>]      \     # [可选]服务端密码
```

客户端:

```
./client -c <配置文件的路径>
        [-f]                # [可选] 强制注册，如果服务器已经有同名服务会覆盖。
```

Docker 客户端：

```
docker run -n fcbreak --host -v /config.ini:<配置文件路径>:ro gzmaxsum/fcbreak-client
```

客户端配置文件:

```
[common]
server = http://<user>:<pass>@<server host>:<server port>
                       # 服务器的API地址，可以设置https或http
heartbeat_interval = 5 # [可选] 心跳间隔，保持到服务器的连接，默认为30s。
skip_verify = false    # [可选] 跳过TLS检测，如果服务器使用的是自签证书，可以使用该项。
request_timeout = 5    # [可选] 访问API的时间限制，默认为5s。
use_ipv6 = false       # [可选] 使用IPv6连接到服务器，一般只需要穿透IPv4，默认为false。
services_info_path =   # [可选] 服务地址等信息的保存位置。默认为/run/fcbreak/services

[ssh]                  # 一个section为一个对外暴露的服务
type = tcp             # 服务类型，目前支持tcp/http/https
# 下面为tcp/http/https均支持的参数
local_ip = 127.0.0.1   # 服务的内网IP
local_port = 22        # 服务的内网端口
bind_ip = 0.0.0.0      # [可选] 在本机绑定的IP，默认为0.0.0.0。
bind_port = 2202       # [可选] 在本机绑定的端口，默认随机设置。
remote_ip = 0.0.0.0    # [可选] 在服务器上暴露的IP，0.0.0.0则为所有IPv4。默认为所有IP。
remote_port = 2200     # [可选] 在服务器上暴露的端口。如果不设置，则不会在服务器暴露端口。

[http_service]         # HTTP类型
type = http            #
local_ip = 127.0.0.1   # 服务的内网IP
local_port = 5000      # 服务的内网端口
remote_ip = 0.0.0.0    # [可选] 在服务器上暴露的IP，0.0.0.0则为所有IPv4。默认为所有IP。
remote_port = 5000     # [可选] 在服务器上暴露的端口。如果不设置，则不会在服务器暴露端口。
# 下面为http/https支持的参数
http_hostname = srv.example.com, srv.foobar.com, \*.example.com, foobar.org.\*
                       # [可选] 注册虚拟服务。注册后可以在服务器监听的HTTP端口访问该网站。
                       # 如服务器监听于:8080，则可以访问srv.example.com:8080。需要将域名指向服务器。
                       # 可以在开始或末尾存在一个通配符。
http_ddns_domain = ddns.example.com
                       # [可选] DDNS域名，如果设置，则转跳时会跳至该域名而不是IP。DDNS需要另外设置。
http_nip_domain = ip.example.com
                       # [可选] NIP域名，如果设置，则转跳时会跳至123-234-123-23.ip.example.com。
                         该设置优先级高于ddns。NIP域名需要自行解析。
http_username=proxy    # [可选] http认证用户名
http_password=password # [可选] http认证密码
http_cache_time = 0    # [可选] 转跳的缓存时间。在缓存期间，浏览器会自动转跳。默认为300s。
http_altsvc = true     # [可选] 使用altsvc代替转跳。
http_backend=https     # [可选] HTTP后端，可选http/https/proxy。proxy详见下面的section

[https_service]        # HTTPS类型
type = https
local_ip = 127.0.0.1   # 服务的内网IP
local_port = 5001      # 服务的内网端口
bind_ip = 0.0.0.0      # [可选] 在本机绑定的IP，默认为0.0.0.0。
bind_port = 5001       # [可选] 在本机绑定的端口，默认随机设置。
remote_ip = 0.0.0.0    # [可选] 在服务器上暴露的IP，0.0.0.0则为所有IPv4。默认为所有IP。
remote_port = 5001     # [可选] 在服务器上暴露的端口。如果不设置，则不会在服务器暴露端口。
http_hostname = srv.example.com, srv.foobar.com, \*.example.com, foobar.org.\*
                       # [可选] 注册虚拟服务。注册后可以在服务器监听的HTTP端口访问该网站。
                       # 如服务器监听于:8080，则可以访问srv.example.com:8080。需要将域名指向服务器。
                       # 可以在开始或末尾存在一个通配符。
http_ddns_domain = ddns.example.com
                       # [可选] DDNS域名，如果设置，则转跳时会跳至该域名而不是IP。DDNS需要另外设置。
http_nip_domain = ip.example.com
                       # [可选] NIP域名，如果设置，则转跳时会跳至123-234-123-23.ip.example.com。
                         该设置优先级高于ddns。NIP域名需要自行解析。
http_username=proxy    # [可选] http认证用户名
http_password=password # [可选] http认证密码
http_cache_time = 0    # [可选] 转跳的缓存时间。在缓存期间，浏览器会自动转跳。默认为300s。
http_altsvc = true     # [可选] 使用altsvc代替转跳。
http_backend=https     # [可选] HTTP后端，可选http/https/proxy。proxy详见下一个section
# 下面为https的参数
https_crt = /certs/example.com.crt # TLS 公钥证书位置
https_key = /certs/example.com.key # TLS 私钥证书位置

[http_proxy]           # http proxy 类型
type = http            # 此类型可对外暴露http/https代理，从而访问更多内网服务。
                       # proxy类型无需设置后端地址
bind_ip = 0.0.0.0      # [可选] 在本机绑定的IP，默认为0.0.0.0。
bind_port = 5012       # [可选] 在本机绑定的端口，默认随机设置。
remote_ip = 0.0.0.0    # [可选] 在服务器上暴露的IP，0.0.0.0则为所有IPv4。默认为所有IP。
remote_port = 5002     # [可选] 在服务器上暴露的端口。如果不设置，则不会在服务器暴露端口。
http_username=proxy    # [可选] http认证用户名
http_password=password # [可选] http认证密码
http_backend=proxy     # 后端为proxy时对外暴露代理
http_proxy_chain=http://localhost:3128
                       # [可选] 级联代理，将请求转发到下一级代理。可以使用http或socks类型。

```

连接器

```
sudo ./connector
    -s http[s]://[<user>:<pass>@]<server host>:<server port> # 服务器 API
    [-i <interval>]               # 更新间隔，默认为 300s
```
