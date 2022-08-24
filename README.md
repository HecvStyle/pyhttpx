# Pyhttpx
基于socket开发的一个网络测试库,供研究https/tls参考
如果你用过requests,它将会变得非常容易

PyPI:
```
$ python -m pip install --upgrade pip
$ python -m pip install pyhttpx
```

**安装依赖**

requirement.txt

```
cryptography==36.0.1
rsa==4.8
pyOpenSSL==21.0.0
brotli==1.0.9

```

## GET
```
>>> import pyhttpx
>>> sess = pyhttpx.HttpSession()
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies={'k':'3301')
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies='k=3301')
>>> r.status_code
200
>>> r.encoding
'utf-8'
>>> r.text
'{\n  "args": {}, ...
>>> r.json
{'args': {},...

```
##### 如果你想知道原生http报文是否达到预期,你可以这样
```
>>> r.request.raw
b'GET /get HTTP/1.1\r\nHost: httpbin.org ...
```

## POST
```
>>> r = sess.post('https://httpbin.org/get',data={})
>>> r = sess.post('https://httpbin.org/get',json={})
```

## HTTP PROXY
```
>>> proxies = {'https': '127.0.0.1:7890'}
>>> proxy_auth = (username, password)
>>> r = sess.post('https://httpbin.org/get',proxies=proxies,proxy_auth=proxy_auth)
```

## 修改tls指纹

- 修改ja3,需要下载wireshark,查看完整握手流程，如果服务器返回已实现的密码套件,可随意魔改client hello包


### 如何禁用firefox的tls1.3, 强制tls1.2

    地址栏输入: about:config,
    搜索tls,将security.tls.version.max的值改为3即可,
    如果firefox访问没问题,表示tls1.2也是可以访问的

### 如何禁用firefox的http2,强制http/1.1
    
    地址栏输入: about:config,
    搜索http2,将network.http.spdy.enabled.http2的值改为false即可,
    如果firefox访问没问题,表示http/1.1也是可以访问的  

**HttpSession 参数说明**

ja3: 指纹构成

exts_payload: 需要填充的扩展数据,不包括数据长度

```
>>>ja3 = '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28-222,29-23-24-25,0'
>>>exts_payload = {222: '\x01'}
>>>sess = pyhttpx.HttpSession(ja3=ja3,exts_payload=exts_payload)
>>>r = sess.get('https://tls.peet.ws/api/all')
>>>r.text
... "ja3": "771,47-49172-52392-53-49200-49195-157-523925,0...
```

# 支持ssl上下文

如果数据为None,表示收到fin,服务器断开连接

```
>>>from pyhttpx.layers.tls.pyssl import SSLContext,PROTOCOL_TLSv1_2
>>>import socket
>>>addres = ('httpbin.org', 443)
>>>context = SSLContext(PROTOCOL_TLSv1_2)
>>>sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
>>>ssock = context.wrap_socket(sock, server_hostname=addres[0])
>>>ssock.connect(addres)
>>>m = 'GET / HTTP/1.1\r\nHOST: %s\r\n\r\n' % addres[0]
>>>ssock.sendall(m.encode())
>>>r = ssock.recv(1024)
b'HTTP/1.0 200 OK\r\n'...
```

# websocket,支持修改ja3

    参考文档tests/test_websockt.py
    
# 版本支持

- tls1.2/tls1.3
- http/1.1

# tls密码套件支持
- TLS13_AES_128_GCM_SHA256(0X1301)
- TLS13_AES_256_GCM_SHA384(0X1302)
- TLS13_CHACHA20_POLY1305_SHA256(0X1303)
- ECDHE_WITH_AES_128_GCM
- ECDHE_WITH_AES_256_GCM
- ECDHE_WITH_CHACHA20_POLY1305_SHA256
- RSA_WITH_AES_128_GCM
- RSA_WITH_AES_256_GCM
- RSA_WITH_AES_128_CBC
- RSA_WITH_AES_256_CBC
- ECDHE_WITH_AES_128_CBC
- ECDHE_WITH_AES_256_CBC


### 附录tls相关资料

   [tls1.2](https://www.rfc-editor.org/rfc/rfc5246.html)  
   [tls1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
 
### end

有什么bug, 或者好设计模式, 欢迎大家issues</br>

如果对你有帮助,可以请我喝杯咖啡哟


 ![Image_QingFlow](https://file.qingflow.com/documents/form/attach/35efbb5c-b704-4ac6-9074-8adc2f0ef9df.png)