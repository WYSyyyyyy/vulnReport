#-*-coding:utf-8 -*-
import random
import hashlib
import requests
import json
import re
import time

#百度开发者信息
#app id
appId = "20180921000210531"

#secret key
secretKey = "l4c0Qj9hPKpy0K9Y6OIj"

#百度  通用翻译API http地址，暂时不用
url = "http://api.fanyi.baidu.com/api/trans/vip/translate?"

#百度  通用翻译API https地址
urls = "https://fanyi-api.baidu.com/api/trans/vip/translate?"



def buildUrl(text):
    salt = random.randint(32768, 65536)
    sign = appId + text + str(salt) + secretKey
    sign = hashlib.md5(sign.encode()).hexdigest()
    fanyiUrl = urls + "q=" + text + "&from=en&to=zh&appid=" + appId + "&salt=" + str(salt) + "&sign=" + sign
    return fanyiUrl

dst = re.compile(r'.*dst\'(.*?)\'.*')

def baiduTrans(text):
    try:
        # print("翻译前：" + text)

        url_trans = buildUrl(text)
        r = requests.get(url_trans)
        data = json.loads(r.text)
        result = data['trans_result'][0]['dst']
        # print("翻译后:"+result)
        return result 
    except Exception as e:
        print(e)
    finally:
        #能力有限，只能单线程。延迟0.5秒避免翻译频繁而导致的出错（0.5是较优值）
        time.sleep(0.5)
        # pass


#这里可以直接调用函数得到结果
# print(baiduTrans("Snoop Servlet information disclosure"))