import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random
import requests
def main():

    url = 'https://tls.peet.ws/api/all'
    #url = 'https://127.0.0.1'
    url = 'https://www.ti.com'

    #firefox99,tls1.2,http/1.1
    ja3 = '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0'

    #chrome103,tls1.3,http/1.1
    ja3 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0'
    exts_payload = {}

    sess = pyhttpx.HttpSession(ja3=ja3)
    p = {'https': '127.0.0.1:7890'}

    r = sess.get(url)
    print(r.status_code)
    print(r.text)




if __name__ == '__main__':
    main()

















