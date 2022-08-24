import logging


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
def default_headers():
    h = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'accept': '*/*',
        'accept-language': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'connection': 'keep-alive',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',

    }

    return h

log = logging.getLogger(__name__)

class Conf:
    debug = False
    max_allow_redirects = 20

def vprint(*args):
    if Conf.debug:
        print(*args)


import sys
from array import array
from collections import abc

from collections.abc import MutableMapping

class M(MutableMapping):

    def __delitem__(self, key):
        del self[key]

    def __getitem__(self, key):
        return getattr(self, key)

    def __iter__(self):
        pass

    def __len__(self):
        return 1

    def __setitem__(self, key, value):
        setattr(self, key, value)




if __name__ == '__main__':
    pass

