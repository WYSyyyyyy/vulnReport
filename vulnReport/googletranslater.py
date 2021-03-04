#-*-coding:utf-8 -*-

import requests
import execjs
import json

#使用谷歌翻译
#py的JS类
class Py4Js():     
  def __init__(self):  
    self.ctx = execjs.compile(""" 
    function TL(a) { 
    var k = ""; 
    var b = 406644; 
    var b1 = 3293161072;       
    var jd = "."; 
    var $b = "+-a^+6"; 
    var Zb = "+-3^+b+-f";    
    for (var e = [], f = 0, g = 0; g < a.length; g++) { 
        var m = a.charCodeAt(g); 
        128 > m ? e[f++] = m : (2048 > m ? e[f++] = m >> 6 | 192 : (55296 == (m & 64512) && g + 1 < a.length && 56320 == (a.charCodeAt(g + 1) & 64512) ? (m = 65536 + ((m & 1023) << 10) + (a.charCodeAt(++g) & 1023), 
        e[f++] = m >> 18 | 240, 
        e[f++] = m >> 12 & 63 | 128) : e[f++] = m >> 12 | 224, 
        e[f++] = m >> 6 & 63 | 128), 
        e[f++] = m & 63 | 128) 
    } 
    a = b; 
    for (f = 0; f < e.length; f++) a += e[f], 
    a = RL(a, $b); 
    a = RL(a, Zb); 
    a ^= b1 || 0; 
    0 > a && (a = (a & 2147483647) + 2147483648); 
    a %= 1E6; 
    return a.toString() + jd + (a ^ b) 
  };      
  function RL(a, b) { 
    var t = "a"; 
    var Yb = "+"; 
    for (var c = 0; c < b.length - 2; c += 3) { 
        var d = b.charAt(c + 2), 
        d = d >= t ? d.charCodeAt(0) - 87 : Number(d), 
        d = b.charAt(c + 1) == Yb ? a >>> d: a << d; 
        a = b.charAt(c) == Yb ? a + d & 4294967295 : a ^ d 
    } 
    return a 
  } 
 """)            
  def getTk(self,text):  
      return self.ctx.call("TL",text)
    
#完成url的拼装
def buildUrl(text,tk):
    #旧版url
    # baseUrl = 'https://translate.google.cn/translate_a/single?client=t&sl=en&tl=zh-CN&hl=zh-CN&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss&dt=t&ie=UTF-8&oe=UTF-8&source=bh&otf=1&ssel=0&tsel=0&kc=1&'
    #新版URL，更加智能一些，把client=webapp即可
    baseUrl = 'https://translate.google.cn/translate_a/single?client=webapp&sl=en&tl=zh-CN&hl=zh-CN&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss&dt=t&ie=UTF-8&oe=UTF-8&source=bh&otf=1&ssel=0&tsel=0&kc=1&'
    baseUrl += 'tk='+str(tk)+'&'
    baseUrl += 'q='+str(text)
    return baseUrl
js = Py4Js()
# def googleTrans(text):
#     try:
#         #get url
#         url = buildUrl(text,js.getTk(text))
#         #responce
#         r = requests.get(url)
#         #返回json格式的数据
#         data = json.loads(r.text)
#         result = data[0][0][0]
#         return result
#     except Exception as e:
#         print("出错了")
#         print(e)

def googleTrans(text):
    url = buildUrl(text,js.getTk(text))
    #responce
    r = requests.get(url)
    #返回json格式的数据
    data = json.loads(r.text)
    result = data[0][0][0]
    return result
