"""
docs
pyhttpx.weboskcts

"""

import asyncio
from pyhttpx.websocket import WebSocketClient

class WSS:
    def __init__(self,url=None, headers=None, loop=None):
        self.url = url
        self.headers = headers
        self.loop = loop
        self.ja3 = '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-55,0-23-65281-10-11-35-16-5-13-28-222,29-23-24-25,0'
        self.exts_payload = {222: '\x00'}

    async def connect(self):
        self.sock = await WebSocketClient(url=self.url, headers=self.headers, loop=self.loop,
                                          ja3=self.ja3,exts_payload=self.exts_payload
                                          ).connect()

    async def send(self):
        while 1:
            await self.sock.send('\x00',binary=True)
            await asyncio.sleep(3)

    async def recv(self):
        while 1:
            r = await self.sock.recv()
            print(r)

def main():
    loop = asyncio.get_event_loop()
    url = 'wss://127.0.0.1:6324'
    headers = {
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',
        'Cache-Control': 'no-cache',
        'Host': '127.0.0.1',
        'Pragma': 'no-cache',
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
        }

    wss = WSS(url, headers, loop)
    loop.run_until_complete(wss.connect())
    loop.create_task(wss.send())
    loop.create_task(wss.recv())
    loop.run_forever()

if __name__ == '__main__':
    main()