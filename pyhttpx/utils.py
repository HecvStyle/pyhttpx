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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/103.0',
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

    t='96d346600cb9d17d324458c680401bcef6ad212b0b0f26a552a9193cd4a15da25d1930c34dde5616645a219b4f0011c9ce82ad84c05ac642f251886cd19d3277e8dd1f64d1016879422486e878de14ca22da0f6e03fcdff9c43268db166f0ce72c2e334a351704ff7d42baf373a8213f7926ae0469b99e38f4609f6da0730cccfc7b7e266c2f42cba0d2d9f99d424c4a36650f33b0fd37e22c4e1c464b6789fcc63ad1d85c895549b630f787ae93ad66c9196b0477ab3993d2e623ba2f19dd35ed404be9124bc7973b74ff0200fba6284e8120afe27f6c82f6be917824db7f527acb2fa1c475c3ee2b303052fa5af5116d180a2c61f1336abebd2a68f29dc2f6f27ca017b1d42c0947c239d22dc1e95a5ed53ee6da75ace644b80ed96aa878b0b7047fcb209502b0f867f285eefd4cd815048b317519c5eeb3e24bed7e3bbed5e7ad84d6756de024a006e785568b9610193baf625775efa0ccfe442327787dbf9f147386ad5a1d44c1c6611c98cd018f58a0018e43876526266d3a6e8ac81a70e0f3803f20c9504941d4a352b4532d96ff53ab1273be43f50b39a54ee51fa1d890a0d86aec5fa21b631d639ea6a5d325dcd96252ba025065d90134ff065758755df3b68be66907e64c30d7743bdd41f710ddcf325697dbf37991f9b0f5295701c305adea9ee4648a18bd7af9fb0f38837a7faacd7f2bfa7de2525693a76852db0638e1266f42889d336335c8ab80673e3dbc5325d940bc12b77a3eb26bef368a252e9ebc17726b4a95168bbb7fee03288aa07c170413cee90e467267e2071e728b717d663c90ccb6b7814a987c7c8b15f908b22ba3d732c325600633d46539abfda9f295202cecb1f8927c09c7c9b03557a365b2e0f5db9814225a5c42af2d8493e3b4f9a8aa0fe5f689f13d5888e3e4e48fcb58fd670b4f6be852ed14408b559f0dfd23e13b2f216cca0702a44967f32189546a873496c784e1ace6e9653b8ff940cb27fc4706f5bbe5df6469a06b57d63f1453d20c6439852e3a2df8571bd96b58010eedcb7fc49e08575e9f20ce3521b967c2a6944d4186b7ac667953b39a24b73631228a341284cc69e641abfcabe8dabebc4789aee4a20ec1ae6b1cbb0cda99439d4607eb3679dbd5391d0e4b2e5211b5cdbc9232ad24ae8c1b2d9aea8db4780535c36195562d6b0a64ca21a71b20938fdd7500f3aee0c5c6a0e2778129158683cbb03cf2e505806ffd4373ef20510ed386a4cc6ae96f56dd4928472fa0f7e1b5699a986fa9b4fc31ffd4c3e120814f1dbbcdc895c5cff5f1c630bbfc8b3309cbdc158bbd40fa25d0d01464c731bc2189b67e3410cc3342bd59eb816f678725830c733a7a7b1f2d1207e9838d1eca22b4804bdd816d9a333c60bd247c4893a294ffeb7d7e6b4cbd59aa2eededc6d7b0328b95fc8b6f7ee7f537f07e040f3591356d220c8fa7dcfaac5643c58dfd0a6a9d323662c1637496385359a329e0daf07ec146b1128e5b7b8ab40e96c421980fb73c76e3a71309b63d2c05a73f84924dc6468b7445f02e55e29fd8ed1fa6ec1eb6f872a6a642b51207a78a27a3937c7e27829e0298f4317076310df17a1eb72cf5fd5028b04617c269fac41e4822d1a632c2c0c6a82f3e2795ea862dbc8fca8300cad48617dd213f0f57792eef4249eddab04c79b9ba1114b8709561a5d24ed06056dfa00837be2061c42d022f76e0a5da39b3091dff3ffc51cb18dace0bf850225f236b1491f4ef7ce951de93b8274d102855ad7449ee0c7f0aa98ed187b5465de161c41a8e5109ed6a01c4c288f1beaafa898feda9793f416123f5203513d2cb842d2f233bfecf324994433a49f4cd1f8733ffcec420d0f4ace1fdf81bb54ae5f5347e0c566c7cacb556bbcc639209cfe139e722a9d11c9087f2d5bd4f34934ed98173def11174bad8f54a83bcc48e75a84774d6d78aea67'
    print(len(bytes.fromhex(t)))

