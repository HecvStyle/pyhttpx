import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random

def main():

    url = 'https://tls.peet.ws/api/all'
    #url = 'https://127.0.0.1'

    ja3 = '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0'
    exts_payload = {222: '\x00'}
    sess = pyhttpx.HttpSession(ja3=ja3, exts_payload=exts_payload)
    proxies = {'https': '127.0.0.1:7890'}
    r = sess.get(url, proxies=proxies, timeout=3, allow_redirects=False)
    print(r.status_code)
    pp(r.json)


if __name__ == '__main__':
    main()
















