
"""
TLS session handler.
"""

import socket
import struct
import time
import platform
import sys
import importlib
import threading

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ec as cg_ec
from cryptography.hazmat.primitives import serialization

from pyhttpx.layers.tls.crypto.ecc import CryptoContextFactory


from pyhttpx.layers.tls.keyexchange import ServerContext,ClientCpiherSpec,ClientKeyExchange
from pyhttpx.layers.tls.handshake import HelloClient
from pyhttpx.layers.tls.suites import CipherSuites
from pyhttpx.layers.tls.extensions import dump_extension


from pyhttpx.layers.tls.tls_context import TLSSessionCtx,TLSSessionCtx13

from pyhttpx.models import Response

from pyhttpx.exception import (
    TLSDecryptErrorExpetion,
    ConnectionTimeout,
    ConnectionClosed,
    ReadTimeout)

from pyhttpx.layers.tls.socks import SocketProxy
from pyhttpx.utils import vprint


PROTOCOL_TLSv1_2 = b'\x03\x03'
PROTOCOL_TLSv1_3 = b'\x03\x04'
def default_context():
    return SSLContext(PROTOCOL_TLSv1_2)


class SSLContext:

    def __init__(self, protocol):
        self.protocol = protocol
        self.check_hostname: bool = False

        self.ciphers = None
        self.exts = None
        self.exts_payload = None
        self.supported_groups = None
        self.supported_groups = None
        self.ec_points = None

        self.tlsversion = b'\x03\x03'

        self.group_x25519_key = b''
        self.group_secp_key = b''



    def set_ja3(self, ja3=None):

        if ja3:
            self.protocol, self.ciphers, self.exts,self.supported_groups,self.ec_points = ja3.split(',')
            self.ciphers = [int(i) for i in self.ciphers.split('-')]
            self.exts = [int(i) for i in self.exts.split('-')]
            self.supported_groups = [int(i) for i in self.supported_groups.split('-')]
            self.ec_points = [int(i) for i in self.ec_points.split('-')]


            self.supported_groups = b''.join([struct.pack('!H', i) for i in self.supported_groups])
            self.ec_points = b''.join([struct.pack('!B', i) for i in self.ec_points])

    def set_ext_payload(self, data):
        self.exts_payload = data
    def wrap_socket(self, sock=None, server_hostname=None):

        return TLSSocket(sock=sock,server_hostname=server_hostname, ssl=self)

    def load_cert_chain(self, certfile: str, ketfile: str):
        pass

class TLSSocket():
    def __init__(self,sock=None, server_hostname=None,ssl=None):

        self._closed = True
        self.server_hostname = server_hostname
        self.sock = sock
        self.context = ssl or default_context()

        self.tls13 = False

    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)

    def connect(self,addres=None, timeout=None, proxies=None, proxy_auth=None):
        self.servercontext = ServerContext()
        self.tls_cxt = TLSSessionCtx()
        self.context.group_x25519_key = self.tls_cxt.group_x25519_key
        self.context.group_secp_key = self.tls_cxt.group_secp_key
        self.tls_cxt.handshake_data = []
        self.host,self.port = addres[0],addres[1]
        self.proxy_auth = proxy_auth
        if not self.sock:          
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.timeout  = timeout
        self.proxies = proxies

        if self.proxies:
            self.sock = SocketProxy(socket.AF_INET, socket.SOCK_STREAM)
            proxy_ip, proxy_port = self.proxies['https'].split(':')
            if self.proxy_auth:
                username,password = proxy_auth[0], proxy_auth[1]
            else:
                username, password = None,None

            self.sock.set_proxy(SocketProxy.HTTP, proxy_ip, proxy_port,username, password )

        try:
            self.sock.connect((self.host, self.port))

        except (ConnectionRefusedError,TimeoutError,socket.timeout):
            raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))

        else:
            self.local_ip, self.local_port = self.sock.getsockname()[:2]
            self.remote_ip, self.remote_port = self.sock.getpeername()[:2]
            self.isclosed = False
            return self._tls_do_handshake13()


    def _tls_do_handshake13(self):

        ciphersuites, extensions = CipherSuites(self.context).dump(),dump_extension(self.host,self.context)
        hello = HelloClient(ciphersuites, extensions)
        self.tls_cxt.client_ctx.random = hello.hanshake.random
        self.sock.sendall(hello.dump(self.tls_cxt))

        cache =b''
        self.server_change_cipher_spec = False
        exchanage = True

        while True:
            try:
                recv = self.sock.recv(2 ** 14)
            except (ConnectionRefusedError,ConnectionResetError,socket.timeout):
                raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))

            recv = cache + recv
            cache = b''
            if recv:
                while recv:
                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]

                    if len(flowtext) != length:
                        cache = recv[:]
                        break

                    recv = recv[5 + length:]
                    if handshake_type == 0x16:
                        if not self.server_change_cipher_spec:
                            self.tls_cxt.handshake_data.append(flowtext)
                            self.servercontext.load(flowtext)
                            self.tls13 = True if self.servercontext.serverstore.ext.get(43) == b'\x03\x04' else False
                            self.tls_cxt.tls13 = self.tls13
                        if not self.tls13:

                            if not exchanage and self.server_change_cipher_spec:
                                #print(threading.current_thread().name,'成功握手,server Encrypted Handshake Message')
                                # 验证服务器消息,Encrypted Handshake Message,效验密钥

                                server_verify_data = self.tls_cxt.decrypt(flowtext, b'\x16')
                                self.tls_cxt.verify_server_message(server_verify_data)
                                return True

                    elif handshake_type == 0x14:
                        if self.tls13:
                            #server Change Cipher Spec
                            self.server_change_cipher_spec = True
                            server_publickey = self.servercontext.serverstore.ext[51][4:]
                            self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                            self.tls_cxt.load_alg()
                            self.tls_cxt.make_secret(server_publickey)

                        else:
                            self.server_change_cipher_spec = True


                    elif handshake_type == 0x17:
                        #tls1.3,握手数据是加密的
                        plaintext = self.tls_cxt.decrypt(flowtext, b'\x17')
                        self.tls_cxt.handshake_data.append(plaintext[:-1])

                        if plaintext[-1:] == b'\x16':
                            plaintext = plaintext[:-1]
                            while plaintext:
                                extlen = struct.unpack('!I', b'\x00' + plaintext[1:4])[0]

                                if plaintext[0] == 0x14:
                                    # finished
                                    changecipherspec = ClientCpiherSpec().dump()
                                    self.sock.sendall(changecipherspec)
                                    verify_data = self.tls_cxt.compute_verify_data()
                                    ciphertext = self.tls_cxt.encrypt(verify_data, b'\x17')

                                    data = b'\x17\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                                    self.sock.sendall(data)

                                    self.tls_cxt.derive_application_traffic_secret()

                                    #ticket数据开始重置sequence
                                    self.tls_cxt.server_ctx.sequence = 0
                                    self.tls_cxt.client_ctx.sequence = 0

                                    self.tls_cxt.server_ctx.crypto_alg.key = self.tls_cxt.server_application_write_key
                                    self.tls_cxt.server_ctx.crypto_alg.fixed_iv = self.tls_cxt.server_application_write_iv

                                    self.tls_cxt.client_ctx.crypto_alg.key = self.tls_cxt.client_application_write_key
                                    self.tls_cxt.client_ctx.crypto_alg.fixed_iv = self.tls_cxt.client_application_write_iv

                                    return


                                elif plaintext[0] == 0x0b:
                                    #证书
                                    pass

                                elif plaintext[0] == 0x0f:
                                    #证书验证
                                    pass
                                elif plaintext[0] == 0x08:
                                    #扩展
                                    pass
                                plaintext = plaintext[4+extlen:]

                    elif handshake_type == 0x15:
                        raise TLSDecryptErrorExpetion('handshake failed!, Server Decrypt Error')

                if not self.tls13:
                    if self.servercontext.done and exchanage:

                        self.tls_cxt.server_ctx.random = self.servercontext.serverstore.random
                        self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                        self.tls_cxt.rsa_pulicKey = self.servercontext.certificatecontext.rsa_pulicKey
                        self.tls_cxt.curve_name = self.servercontext.curve_name
                        self.tls_cxt.server_ecdhe_pubkey = self.servercontext.serverpubkey
                        if 23 in self.servercontext.serverstore.ext.keys():
                            self.tls_cxt.extended_master_secret = True

                        # 加载相关套件
                        self.tls_cxt.load_alg()

                        keychange = ClientKeyExchange(self.tls_cxt.publickey_bytes).dump(self.tls_cxt)
                        changecipherspec = ClientCpiherSpec().dump()

                        # 加载客户端verify_data后再导出密钥
                        self.tls_cxt.load_key()

                        verify_data = self.tls_cxt.get_verify_data()
                        ciphertext = self.tls_cxt.encrypt(verify_data, b'\x16')
                        encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                        self.sock.sendall(keychange + changecipherspec + encrypted_message)
                        exchanage = False


    def _tls_do_handshake(self):

        ciphersuites, extensions = CipherSuites(self.context).dump(),dump_extension(self.host,self.context)
        hello = HelloClient(ciphersuites, extensions)
        self.tls_cxt.client_ctx.random = hello.hanshake.random
        self.sock.sendall(hello.dump(self.tls_cxt))

        exchanage  = True
        cache =b''
        self.server_change_cipher_spec = False
        while True:
            try:
                recv = self.sock.recv(6324)

            except (ConnectionRefusedError,ConnectionResetError,socket.timeout):
                raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))

            recv = cache + recv
            cache = b''

            if recv:
                while recv:
                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]
                    if len(flowtext) != length:
                        cache = recv[:]
                        break

                    if handshake_type == 0x16:

                        #在发送verify_data处理握手层数据
                        if not self.server_change_cipher_spec:
                            self.tls_cxt.handshake_data.append(flowtext)
                            self.servercontext.load(flowtext)

                        if not exchanage and self.server_change_cipher_spec:
                            #print(threading.current_thread().name,'成功握手,server Encrypted Handshake Message')
                            # 验证服务器消息,Encrypted Handshake Message,效验密钥

                            server_verify_data = self.tls_cxt.decrypt(flowtext, b'\x16')
                            self.tls_cxt.verify_server_message(server_verify_data)
                            return True

                    elif handshake_type == 0x14:
                        self.server_change_cipher_spec = True
                    elif handshake_type == 0x15:
                        raise TLSDecryptErrorExpetion('handshake failed!, Server Decrypt Error')
                    recv = recv[5+length:]

                if self.servercontext.done and exchanage:

                    self.tls_cxt.server_ctx.random = self.servercontext.serverstore.random
                    self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                    self.tls_cxt.rsa_pulicKey = self.servercontext.certificatecontext.rsa_pulicKey
                    self.tls_cxt.curve_name = self.servercontext.curve_name
                    self.tls_cxt.server_ecdhe_pubkey = self.servercontext.serverpubkey
                    if 23 in self.servercontext.serverstore.ext.keys():
                        self.tls_cxt.extended_master_secret = True

                    #加载相关套件
                    self.tls_cxt.load_alg()

                    keychange = ClientKeyExchange(self.tls_cxt.publickey_bytes).dump(self.tls_cxt)
                    changecipherspec =  ClientCpiherSpec().dump()

                    #加载客户端verify_data后再导出密钥
                    self.tls_cxt.load_key()

                    verify_data = self.tls_cxt.get_verify_data()
                    ciphertext = self.tls_cxt.encrypt(verify_data, b'\x16')
                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext )) + ciphertext
                    self.sock.sendall(keychange + changecipherspec + encrypted_message)
                    exchanage = False



    def flush(self):

        self.sock.sendall(self.write_buff)
        self.write_buff = None
        self.plaintext_buffer_reader = []
        cache = b''
        read_ended = False
        while not read_ended:

            #timeout=0,会设置非阻塞
            self.timeout > 0 and self.sock.settimeout(self.timeout)
            #self.sock.settimeout(None)
            try:
                recv = self.sock.recv(6324)
            except ConnectionAbortedError:
                raise ConnectionAbortedError('ConnectionAbortedError')

            except socket.timeout:
                raise ReadTimeout('timed out')

            if not recv:
                # 服务器不保持长连接,传输完毕断开连接
                self.isclosed = True
                read_ended = True
            recv = cache + recv
            cache = b''
            while recv and len(recv) >= 5:
                handshake_type = struct.unpack('!B', recv[:1])[0]
                length = struct.unpack('!H', recv[3:5])[0]
                flowtext = recv[5:5 + length]
                if len(flowtext) != length:
                    cache = recv[:]
                    break

                recv = recv[5 + length:]
                if handshake_type == 0x17:
                    plaintext = self.tls_cxt.decrypt(flowtext, b'\x17')
                    self.response.flush(plaintext)
                    if self.response.read_ended:
                        read_ended  = True
                        if self.response.headers.get('connection') != 'keep-alive':
                            self.isclosed = True

                elif handshake_type == 0x15:
                    read_ended = True
                    self.isclosed = True


    def send(self, plaintext):

        self.response = Response()
        ciphertext = self.tls_cxt.encrypt(plaintext, b'\x17')
        self.write_buff = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        return self.flush()

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sendall(self, plaintext):

        #self.tls13 = True
        if self.tls13:
            plaintext += b'\x17'

        #time.sleep(2)
        ciphertext = self.tls_cxt.encrypt(plaintext, b'\x17')
        self.write_buff = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        self.sock.sendall(self.write_buff)
        self.cache = b''
        self.plaintext_reader = b''

    def recv(self, size=1024):

        s = self.sock.recv(size)
        if not s:
            return None

        s = self.cache + s
        self.cache = b''

        #会存在读取长度不足而返回空字符,而不是收到fin
        while s and len(s) >= 5:

            handshake_type = struct.unpack('!B', s[:1])[0]
            length = struct.unpack('!H', s[3:5])[0]
            flowtext = s[5:5 + length]

            if len(flowtext) < length:
                self.cache = s[:]
                break

            s = s[5 + length:]

            if handshake_type == 0x17:
                if self.tls13:
                    p = self.tls_cxt.decrypt(flowtext, b'\x17')
                    p, t = p[:-1], p[-1]
                    if t == 22:
                        #ticket session
                        pass
                    elif t == 23:
                        self.plaintext_reader += p

                else:
                    p = self.tls_cxt.decrypt(flowtext, b'\x17')
                    self.plaintext_reader += p

            elif handshake_type == 0x15:
                self.isclosed = True

        b = self.plaintext_reader
        self.plaintext_reader = b''
        return b


if __name__ == '__main__':
    host = '127.0.0.1'
    host = 'www.ti.com'
    port = 443
    addres = (host,port)

    context = SSLContext(PROTOCOL_TLSv1_2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ssock = context.wrap_socket(sock, server_hostname=host)
    ssock.connect(addres)
    m = 'GET / HTTP/1.1\r\nHOST: %s\r\n\r\n' % host
    ssock.sendall(m.encode())
    p = b''
    response = Response()
    while 1:
        r = ssock.recv(1024)
        if r is None:
            break
        else:
            p += r
            response.flush(r)
        if response.read_ended:
            break

    print(response.text)
