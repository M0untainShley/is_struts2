#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

# @Author : shley
# @Time : 2023/3/1 16:45
import random
import string
import time
import argparse
import re
import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

ERROR_KEYS = ['Struts Problem Report', 'org.apache.struts2', 'struts.devMode', 'struts-tags',
              'There is no Action mapped for namespace']

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0"
}


# check suffix :.do,.action
def check_by_suffix(page_res_json):
    if page_res_json['code'] == 404:
        return False
    html = page_res_json['html']
    match_action = re.findall(r"""(['"]{1})(/?((?:(?!\1|\n|http(s)?://).)+)\.action)(\?(?:(?!\1).)*)?\1""", html,
                              re.IGNORECASE)

    match_do = re.findall(r"""(['"]{1})(/?((?:(?!\1|\n|http(s)?://).)+)\.do)(\?(?:(?!\1).)*)?\1""", html,
                          re.IGNORECASE)

    if len(match_do) + len(match_action) > 0 and (".action" in str(match_action) or ".do" in str(match_do)):
        return True
    else:
        return False


# check dev mode page
def check_dev_mode(url):
    dev_mode_url = url + "/struts/webconsole.html"
    info = get_html(dev_mode_url)

    if info['code'] == 200 and "Welcome to the OGNL console" in info['html']:
        return True
    else:
        return False


# check error msg
def check_actions_errors(url):
    error_path = [url + "/?actionErrors=1111", url + "/tmp2017.action", url + "/tmp2017.do",
                  url + "/system/index!testme.action", url + "/system/index!testme.do"]

    for test_url in error_path:
        info = get_html(test_url)
        for error_message in ERROR_KEYS:
            if error_message in info['html'] and info['code'] == 500:
                print("[+] found error_message:", error_message)
                return True
    return False


# check add random str
def check_add_random_path(url):
    random_path = generate_random_str()
    parsed_url = urlparse(url)
    if len(parsed_url.query) != 0:
        url = parsed_url.scheme + "://" + parsed_url.netloc + "/" + random_path + parsed_url.path + "?" + parsed_url.query
    else:
        url = parsed_url.scheme + "://" + parsed_url.netloc + "/" + random_path + parsed_url.path

    res = requests.get(url, timeout=3, headers=headers, allow_redirects=True, verify=False)
    if res.status_code == 200:
        return True
    else:
        return False


# check CheckboxInterceptor
def check_check_box(url):
    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):

        info = get_html(url.replace(match.group('parameter'), "__checkbox_" + match.group('parameter')))
        check_key = 'name="{}"'.format(match.group('parameter'))
        check_value = 'value="false"'

        html = info['html']
        match_input_tags = re.findall(r"""<\s*input[^>]*>""", html, re.IGNORECASE)
        for input_tag in match_input_tags:
            if check_key in input_tag and check_value in input_tag:
                return True

    return False


# check I18N -> internationalization and localization
def check_i18n(url):
    info_origin = get_html(url)
    time.sleep(0.5)
    info_zhCN = get_html(url + "?" + 'request_locale=zh_CN')
    time.sleep(0.5)
    info_enUS = get_html(url + "?" + 'request_locale=en_US')
    time.sleep(0.5)

    if "request_locale=zh_CN" in info_origin['html'] and "request_locale=en_US" in info_origin['html']:
        return True

    if abs(len(info_zhCN['html']) - len(info_enUS['html'])) > 1024:
        return True

    return False


# check default .css
# 低版本的 struts2 可能不存在此文件，因此此项仅作为一个辅助手段
def check_default_css(target):
    css_path = target + "/struts/domTT.css"
    ctx = get_html(css_path)
    req = requests.get(url, timeout=3, headers=headers, allow_redirects=True, verify=False)
    if req.status_code == 200 and "Licensed to" in ctx['html']:
        return True

    return False


# 生成 16 位随机随机字符串
def generate_random_str(length=16):
    """
    生成一个指定长度的随机字符串，其中
    string.digits=0123456789
    string.ascii_letters=abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
    """
    str_list = [random.choice(string.digits + string.ascii_letters) for i in range(length)]
    random_str = ''.join(str_list)
    return random_str


# 获取网页源代码
def get_html(url):
    res = requests.get(url, timeout=3, headers=headers, allow_redirects=True, verify=False)
    content = res.text

    return {"html": content, "code": res.status_code, "url": url}


# 对传入进来的 url 进行格式化
def format_url(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    return url


def check_is_struts2(url):
    url = format_url(url)

    # 得到页面内容 html 代码
    index_html = get_html(url)

    # 1. 判断是否存在 dev mode 页面
    if check_dev_mode(url):
        return "[success] %s is struts2! [check_dev_mode]" % url

    # 2. 判断网页代码中是否存在 .do 或者 .action 连接
    if check_by_suffix(index_html):
        return "[success] %s is struts2! [check_by_suffix]" % url

    # 3. 判断页面中的错误信息
    if check_actions_errors(url):
        return "[success] %s is struts2! [check_actions_errors]" % url

    # 4. 添加随机路径，看页面是否仍可以访问
    if check_add_random_path(url):
        return "[success] %s is struts2! [check_add_random_path]" % url

    # 5.
    if check_check_box(url):
        return "[success] %s is struts2! [check_check_box]" % url

    # 6. 检测 i18n
    if check_i18n(url):
        return "[success] %s is struts2! [check_i18n]" % url

    # 7. 判断网站是否存在 /struts/domTT.css 文件
    if check_default_css(url):
        return "[success] %s is struts2! [check_default_css]" % url

    return False


if __name__ == "__main__":
    # 接受单个 url 以及 file 文件
    parser = argparse.ArgumentParser(description=" struts2 框架检测脚本")
    parser.add_argument("-u", "--url", help="target URL")
    parser.add_argument("-f", "--file", help="file containing target URLs (one per line)")
    args = parser.parse_args()

    if args.url:
        result = check_is_struts2(args.url)
        if not result:
            print("[*] %s is not struts2!" % args.url)
        else:
            print(result)
    elif args.file:
        with open(args.file) as f:
            for line in f:
                url = line.strip()
                result = check_is_struts2(url)
                if not result:
                    print("[*] %s is not struts2!" % url)
                else:
                    print(result)
    else:
        parser.print_help()
