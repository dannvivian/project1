# -*- coding: utf-8 -*-
# @Time    : 2018/8/30 下午2:13
# @Author  : WangJuan
# @File    : Parse.py
"""
封装各种加密方法

"""
from hashlib import sha1
from hashlib import md5
# from Crypto.Hash import SHA256
# from Crypto.Cipher import AES
# from Crypto.Cipher import DES
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5
import binascii
import base64
import logging as log
import re


def get_file_md5(filename):
    """
    获取文件的md5值
    :param filename: 目标文件
    :return: 文件的MD5值
    """
    with open(filename, 'rb') as file:
        text = file.read()
        md = md5()
        md.update(text)
        return md.hexdigest()


def my_md5(msg):
    """
    md5 算法加密
    :param msg: 需加密的字符串
    :return: 加密后的字符
    """
    hl = md5()
    hl.update(msg.encode('utf-8'))
    return hl.hexdigest()


def my_sha1(msg):
    """
    sha1 算法加密
    :param msg: 需加密的字符串
    :return: 加密后的字符
    """
    sh = sha1()
    sh.update(msg.encode('utf-8'))
    return sh.hexdigest()


def my_sha256(msg):
    """
    sha256 算法加密
    :param msg: 需加密的字符串
    :return: 加密后的字符
    """
    sh = SHA256.new()
    sh.update(msg.encode('utf-8'))
    return sh.hexdigest()


def my_des(msg, key):
    """
    DES 算法加密
    :param msg: 需加密的字符串,长度必须为8的倍数，不足添加'='
    :param key: 8个字符
    :return: 加密后的字符
    """
    de = DES.new(key, DES.MODE_ECB)
    mss = msg + (8 - (len(msg) % 8)) * '='
    text = de.encrypt(mss.encode())
    return binascii.b2a_hex(text).decode()


def my_aes_encrypt(msg, key, vi):
    """
    AES 算法的加密
    :param msg: 需加密的字符串
    :param key: 必须为16，24，32位
    :param vi: 必须为16位
    :return: 加密后的字符
    """
    obj = AES.new(key, AES.MODE_CBC, vi)
    txt = obj.encrypt(msg.encode())
    return binascii.b2a_hex(txt).decode()


def my_aes_decrypt(msg, key, vi):
    """
    AES 算法的解密
    :param msg: 需解密的字符串
    :param key: 必须为16，24，32位
    :param vi: 必须为16位
    :return: 加密后的字符
    """
    msg = binascii.a2b_hex(msg)
    obj = AES.new(key, AES.MODE_CBC, vi)
    return obj.decrypt(msg).decode()


# 返回字符串
def base64_decode(temp):
    """
    base64解码
    :param temp:需要解码的base64字符串
    :return:解码后的字符串
    """
    return str(base64.b64decode(temp.encode("utf-8")), "utf-8")


# 返回字符串
def base64_encode(temp):
    """
    base64编码
    :param temp:需要编码的字符串
    :return:base编码后的字符串

    """

    return str(base64.b64encode(temp.encode('utf-8')), 'utf-8')


def D_base64_decode(temp):
    """
    base64解码：解决base64有等号的问题
    :param temp:需要解码的base64字符串
    :return:解码后的字符串
    """
    temp = temp.replace(",", "+")
    temp = temp.replace(":", "=")
    temp = temp.replace(".", "//")
    temp = bytes(temp, encoding='utf-8')
    dStr = base64.b64decode(temp).decode()
    log.debug("BASE64 Decode result is: \n" + dStr)
    return dStr


def D_base64_encode(temp):
    """
      base64编码：解决base64有等号的问题
      :param temp:需要编码的字符串
      :return:base编码后的字符串

    """
    # temp = bytes(temp,encoding='utf-8')
    eStr = str(base64.b64encode(temp.encode('utf-8')), 'utf-8')
    eStr = eStr.replace(r"+", r",")
    eStr = eStr.replace(r"=", r":")
    eStr = re.sub(r'/', r'.', eStr)

    log.debug("BASE64 encode result is: \n" + eStr)
    return eStr


def Asm_base64_encode(temp):
    """
      base64编码：解决base64有等号的问题
      :param temp:需要编码的字符串
      :return:base编码后的字符串

    """
    # temp = bytes(temp,encoding='utf-8')
    # eStr = str(base64.b64encode(temp.encode('utf-8')), 'utf-8')
    eStr = str(temp)
    eStr = eStr.replace(r"+", r",")
    eStr = eStr.replace(r"=", r":")
    eStr = re.sub(r'/', r'.', eStr)

    log.debug("BASE64 encode result is: \n" + eStr)
    return eStr

def Asm_base64_decode(temp):
    """
    base64解码：解决base64有等号的问题
    :param temp:需要解码的base64字符串
    :return:解码后的字符串
    """
    temp = temp.replace(",", "+")
    temp = temp.replace(":", "=")
    temp = temp.replace(".", "//")
    dStr = temp
    log.debug("BASE64 Decode result is: \n" + dStr)
    return dStr


def rsa_encrypt(msg, key):
    """
    rsa加密
    :param msg:需要加密的字符串
    :param key:公钥
    :return:加密后的字符串
    """
    publickey = RSA.importKey(key)
    # 进行加密
    pk = PKCS1_v1_5.new(publickey)
    encrypt_text = pk.encrypt(msg.encode())
    # 加密通过base64进行编码
    res = base64.b64encode(encrypt_text)
    return res


def unicode_to_utf8(temp_str):
    """
    unicode转utf8
    Args:
        temp_str: 字符串

    Returns:

    实例：
    "%u5DF2%u7981%u7528Guest%u7528%u6237"转为：已禁用Guest用户

    """
    return temp_str.replace("%u", "\\u").encode("gbk").decode("unicode_escape")


def utf8_to_unicode(temp_str):
    return temp_str.encode("unicode_escape").decode("utf-8").replace("\\u", "%u")


if __name__ == '__main__':
    result = base64_decode("")
