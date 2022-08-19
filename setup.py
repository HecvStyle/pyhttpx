from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import sys

install_requires = [
    "cryptography==36.0.1",
    "rsa==4.8",
    "pyOpenSSL==21.0.0",
    "brotli"]

test_requirements = [
    "pytest>=3",
]

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, because outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)



packages = find_packages()
setup(
    name = "pyhttpx",   #这里是pip项目发布的名称
    version = "1.2.32",  #版本号，数值大的会优先被pip
    keywords = ["pip", "pyhttpx"],			#关键字
    description = "HTTP library.",	#描述
    long_description = "3301's private utils.",
    license = "MIT Licence",		# 许可证

    url = "https://github.com/zero3301/pyhttpx",     #项目相关文件地址，一般是github项目地址即可
    author = "3301",			# 作者
    author_email = "1114135928@qq.com",
    package_dir={"pyhttpx": "pyhttpx"},
    zip_safe=False,
    # package_data={
    #     # 包含文件后缀,此时include_package_data = False,或者使用MANIFEST.in构建
    #     '': ['*.pyd', '*.so']},

    packages = packages,
    include_package_data = True,
    platforms = "any",
    install_requires = install_requires,
    cmdclass={'test': PyTest},
    tests_require=test_requirements,

)

#打包
#python setup.py sdist
#twine upload dist/pyhttpx-1.2.31.tar.gz
