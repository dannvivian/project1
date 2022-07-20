# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

#
# def print_hi(name):
#     # Use a breakpoint in the code line below to debug your script.
#     print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
import json
import re
import logging as log
import requests
import pytest
import execjs
import Parse
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0","X-Requested-With":"XMLHttpRequest"}
params={}


class TestLogin:
    def test01(self,pre_login):
        print(pre_login.text)
        print(pre_login.cookies)
        print(pre_login.status_code)
        log.debug(f"返回状态码:{pre_login.status_code}")


if __name__ == '__main__':
    pytest.main(["-vs"])
    # print(req.json())
    # dic1 = {"aaa":"cc","bb1":"33"}

    # print(req.json())
    # print(req.text)
    # print(req.status_code)
    # print(req.reason)
    # print(req.encoding)
    # print((req.headers))