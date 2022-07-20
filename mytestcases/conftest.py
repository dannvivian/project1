import json

import pytest
import requests


@pytest.fixture(scope='session')
def  pre_login():
        sever_ip = "172.29.166.10"
        json_data = {
            "account":"admin",
            "password":"888888"
        }
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
                    "X-Requested-With": "XMLHttpRequest"}

        port = "8443"
        # 首先获取加密信息
        request_url = f"https://{sever_ip}:{port}/backend/api/encrypt"
        res = requests.post(url=request_url,headers=headers,data=json_data,verify=False)
        login_crypt = json.loads(res.text)
#         然后再登录
        login_url = f"https://{sever_ip}:{port}/backend/api/login"
        login_res = requests.post(url=login_url,headers=headers,data=login_crypt,verify=False)
        return login_res
        # print(login_res.text)
        # print(login_res.cookies)

