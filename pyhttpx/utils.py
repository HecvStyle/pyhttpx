import logging
from collections import defaultdict


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

class IgnoreCaseDict(defaultdict):
    #忽略key大小写
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._keys = {}

    def __delitem__(self, key):
        super().__delitem__(key)

    def __getitem__(self, key):
        return super().__getitem__(key)


    def __setitem__(self, key, value):

        k = self._keys.get(key.lower())
        if k:
            self.__delitem__(k)

        super().__setitem__(key,value)
        self._keys[key.lower()] = key

    def update(self, d ,**kwargs) -> None:
        for k, v in d.items():
            self.__setitem__(k ,v)


def default_headers():
    h = {
        'Host': '127.0.0.1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'Accept': '*/*',
        'Accept-Language': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',

    }
    d = IgnoreCaseDict()
    d.update(h)
    return d


log = logging.getLogger(__name__)

class Conf:
    debug = False
    max_allow_redirects = 20

def vprint(*args):
    if Conf.debug:
        print(*args)




if __name__ == '__main__':
    h = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'accept': '*/*',
        'accept-language': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'connection': 'keep-alive',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',

    }
    a = MutDict()

    a.update(h)
    h1 = {
        'user-agent': '1',
        'User-Agent': '1',

    }
    a.update(h1)
    for k,v in a.items():
        print(k,v)

