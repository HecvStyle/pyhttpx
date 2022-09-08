import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random

import concurrent
import threading
import requests

test_chrome_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

def main():

    url = 'https://tls.peet.ws/api/all'

    url = 'https://127.0.0.1'
    url = 'https://httpbin.org/get'


    #ja3和User-Agent建议使用同一个浏览器的信息
    #firefox99,tls1.2,http/1.1
    ja3 = '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0'

    #chrome103,tls1.3,http/1.1
    ja3 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0'

    sess = pyhttpx.HttpSession(ja3=ja3)
    p = {'https': '127.0.0.1:7890'}
    p = None

    r = sess.get(url)
    text  = r.text

    print(r.status_code)
    print(len(text))
    print(text)


def test_concurrent():
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        #results = executor.map(main,range(3))
        task = [executor.submit(main) for i in range(10)]
        for future in concurrent.futures.as_completed(task):
            try:
                data = future.result()
            except Exception as exc:
                print(exc)

    executor.shutdown(wait=True)

if __name__ == '__main__':

    main()
    #test_concurrent()
























