import pkg_resources
import sys
import os
import urllib.request
import urllib.error
import urllib.parse
import socket
import subprocess


class RequirementsCtrl:
    is_init = False
    pip_source_name = "default"
    pip_source = "https://pypi.python.org/simple"
    pip_sources = {
        '阿里云': 'https://mirrors.aliyun.com/pypi/simple/',
        '腾讯云': 'https://mirrors.cloud.tencent.com/pypi/simple/',
        '北外大学': 'https://mirrors.bfsu.edu.cn/pypi/web/simple',
        '清华大学': 'https://pypi.tuna.tsinghua.edu.cn/simple',
        '网易': 'https://mirrors.163.com/pypi/simple/',
    }

    @classmethod
    def init_source(cls):
        if not cls.is_init:
            try:
                back = list(cls.pip_sources.items())
                while not cls.test_url(cls.pip_source):
                    if not back:
                        cls.pip_source_name = cls.pip_source = None
                        break
                    cls.pip_source_name, cls.pip_source = back.pop(0)
            except:
                cls.pip_source_name = cls.pip_source = None
            cls.is_init = True
        return cls.pip_source_name is not None

    @staticmethod
    def test_url(url):
        try:
            code = urllib.request.urlopen(url, timeout=5).getcode()
            return code == 200, code
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as error:
            return False, error

    @staticmethod
    def test_requirements(arg):
        try:
            pkg_resources.require(arg)
        except pkg_resources.DistributionNotFound:
            return False
        except pkg_resources.VersionConflict:
            return False
        else:
            return True

    @classmethod
    def auto_install_requirements(cls, *arg):
        if not cls.test_requirements(arg):
            cls.sub_process_install(arg)
            if not cls.test_requirements(arg):
                raise Exception("Failed to install requirements")

    @classmethod
    def sub_process_install(cls, pkgs):
        if not cls.init_source():
            raise Exception("No valid source for pip")
        subprocess.Popen([
            os.environ.get('python_interpreter') or sys.executable,
            '-m', 'pip', 'install', *pkgs,
            '-i', cls.pip_source, '--trusted-host', urllib.parse.urlsplit(cls.pip_source).netloc
        ]).communicate()
