# -*- coding=utf-8 -*-
 
from bs4 import BeautifulSoup as bs
import re
import googletranslater






def zhengli(fileName, info_flag):
    # 'r'时出现"UnicodeDecodeError: 'gbk' codec can't decode byte 0x80 in position 205: illegal multibyte sequence"
    #错误，方法一：r 后加encoding='utf-8';法二，'rb'
    #20200116 使用法一出现“UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte，
    #故用encoding='unicode_escape' or encoding='gbk'
    #打开文件
    # print(info_flag)
    with open(fileName, 'r', encoding='unicode_escape') as f:
    # with open(fileName, 'rb') as f:
        text = ''.join(f.readlines())
        text1 = text.replace('<td colspan="16" class="s37">Acunetix Website Audit</td>', '')
        text2 = text1.replace('<td class="s37" colspan="16">Acunetix Website Audit</td>', '')
        html = bs(text2, "html.parser")
        
        # html.replace('<td colspan="16" class="s37">Acunetix Website Audit</td>','')
        url = ''
        #变量声明，使用risk level分成3个列表代替排序
        awvs_list, risk_high, risk_medium, risk_low = [],[],[],[]

        #baseurl为基础地址，如http:192.168.1.2:8080
        awvs_baseURL = str(html.find(text=re.compile('^Scan of'))).replace('Scan of ', '').split('/')

        baseurl = awvs_baseURL[0]+"//"+awvs_baseURL[2]
        #得到Alert group的坐标，个人认为是最优选择。因为上面就是参数或URL，比较方便选择。
        #涉及到的 s10 之类的为class值，如模板改变，需改变相应的值。
        #s30为 alert group
        # tmps = html.find_all(class_=re.compile('^s30'), text='Alert group')
        tmps = html.find_all(class_=re.compile('^s'), text='Alert group')

        for tmp in tmps:
            #s31为漏洞等级
            # risk_level = tmp.find_next(class_=re.compile('^s31')).get_text()
            risk_level = tmp.find_next(class_=re.compile('^s'), text='Severity').find_next(class_=re.compile('^s')).get_text()
            #如果是消息级别不整理
            

            #如果是高级别，则放到一个单独的list里，后续2个都一样
            if risk_level == "High":
                #awvs的参数不是每个漏洞都有，没有的漏洞在HTML里也没有体现parameter这个字段，所以这里采取不记录这个字段
                #有则跳过，没有则找漏洞URL
                if "Parameter" in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = tmp.find_previous(class_=re.compile('^s')).find_previous(class_=re.compile('^s')).get_text()
                #因为漏洞URL这个字段也不是每个漏洞都有，HTML中也相应没有这个字段，所以要查找上个漏洞的详情确定是否存在URL
                #awvs这个HTML排版 任性得很
                elif 'Connection: Keep-alive' in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = ''
                else:
                    url = tmp.find_previous(class_=re.compile('^s')).get_text()
                #一系列折腾得到的URL，居然还会有web server、'/' 和 ''这几种操作
                if url == 'Web Server' or url == '':
                    awvs_url = baseurl + '/'
                else:
                    #拼接得到完整URL
                    awvs_url = baseurl + url

                
                # alert group 后一个是漏洞名字
                awvs_name = tmp.find_next(class_=re.compile('^s')).get_text()
                #awvs_risk = tmp.find_next(class_=re.compile('^s31')).get_text()
                #因为确定是高，直接写高了
                awvs_risk = "高"
                # awvs_url = 
                #Recommendations 后一个是解决方案
                awvs_solution = tmp.find_next(class_=re.compile('^s'), text='Recommendations').find_next(class_=re.compile('^s')).get_text()
                risk_high.append([awvs_name, awvs_risk, awvs_url, awvs_solution])
            #和上面注释一样
            elif risk_level == "Medium":

                if "Parameter" in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = tmp.find_previous(class_=re.compile('^s')).find_previous(class_=re.compile('^s')).get_text()
                elif 'Connection: Keep-alive' in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = ''
                else:
                    url = tmp.find_previous(class_=re.compile('^s')).get_text()
                if url == 'Web Server' or url == '':
                    awvs_url = baseurl + '/'
                else:
                    awvs_url = baseurl + url

                
                awvs_name = tmp.find_next(class_=re.compile('^s')).get_text()
                #awvs_risk = tmp.find_next(class_=re.compile('^s31')).get_text()
                awvs_risk = "中"
                # awvs_url = 
                awvs_solution = tmp.find_next(class_=re.compile('^s'), text='Recommendations').find_next(class_=re.compile('^s')).get_text()
                risk_medium.append([awvs_name, awvs_risk, awvs_url, awvs_solution])

            elif risk_level == "Low":

                if "Parameter" in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = tmp.find_previous(class_=re.compile('^s')).find_previous(class_=re.compile('^s')).get_text()
                elif 'Connection: Keep-alive' in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = ''
                else:
                    url = tmp.find_previous(class_=re.compile('^s')).get_text()
                if url == 'Web Server' or url == '':
                    awvs_url = baseurl + '/'
                else:
                    awvs_url = baseurl + url

                
                awvs_name = tmp.find_next(class_=re.compile('^s')).get_text()
                #awvs_risk = tmp.find_next(class_=re.compile('^s31')).get_text()
                awvs_risk = "低"
                # awvs_url = 
                awvs_solution = tmp.find_next(class_=re.compile('^s'), text='Recommendations').find_next(class_=re.compile('^s')).get_text()
                risk_low.append([awvs_name, awvs_risk, awvs_url, awvs_solution])
            elif  risk_level == 'Informational' and info_flag:
                if "Parameter" in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = tmp.find_previous(class_=re.compile('^s')).find_previous(class_=re.compile('^s')).get_text()
                elif 'Connection: Keep-alive' in tmp.find_previous(class_=re.compile('^s')).get_text():
                    url = ''
                else:
                    url = tmp.find_previous(class_=re.compile('^s')).get_text()
                if url == 'Web Server' or url == '':
                    awvs_url = baseurl + '/'
                else:
                    awvs_url = baseurl + url

                
                awvs_name = tmp.find_next(class_=re.compile('^s')).get_text()
                #awvs_risk = tmp.find_next(class_=re.compile('^s31')).get_text()
                awvs_risk = "低"
                # awvs_url = 
                awvs_solution = tmp.find_next(class_=re.compile('^s'), text='Recommendations').find_next(class_=re.compile('^s')).get_text()
                risk_low.append([awvs_name, awvs_risk, awvs_url, awvs_solution])
            # awvs_list.append([awvs_name, awvs_risk, awvs_url, awvs_solution])
        #list按漏洞名称排序，方便合并URL
        risk_high.sort(key=takeName)    
        risk_medium.sort(key=takeName)    
        risk_low.sort(key=takeName)    

        #把三个列表合并成一个列表
        awvs_list.extend(risk_high)
        awvs_list.extend(risk_medium)
        awvs_list.extend(risk_low)

        list1 = []
        #如果有相同的就去重，以防万一
        for x in awvs_list:
            if x not in list1:
                list1.append(x)
        
        #合并URL
        new_list = hebing_url(list1)

        #翻译
        for x in new_list:
            x[0] = googletranslater.googleTrans(x[0])
            x[3] = googletranslater.googleTrans(x[3])

        return ("URL地址", new_list)

def takeName(elem):
    return elem[0]
      
    
def hebing_url(listHe):
    #获取列表长度
    listHe.append(["", "", "", ""])
    list_len = len(listHe)
    #设置临时变量，作为缓冲输出
    tmp_name, tmp_risk, tmp_urls, tmp_solution = listHe[0][0], listHe[0][1], listHe[0][2], listHe[0][3]
    #接收列表
    new_list = []
    #计数器，最多纪录5个url
    i = 5
    #循环获取每一个漏洞，这次比较完输出上个漏洞的情况。
    for x in range(list_len):
        #如果漏洞name一样，则合并url
        if listHe[x][0] == tmp_name:  #and listHe[x][1] != tmp_host
            #如果初始ip和第一项IP一样则pass，主要针对第一个漏洞情况
            if tmp_urls != listHe[x][2] and i > 1 :
                i = i - 1
                tmp_urls = tmp_urls + '\n' + listHe[x][2]
        #输出漏洞详情和设置新的tmp_host
        else:   # listHe[x][2] != tmp_name:  #and tmp_host1 != ""
            i = 5
            new_list.append([tmp_name, tmp_risk, tmp_urls, tmp_solution])
            tmp_urls = listHe[x][2]
        #设置这次的漏洞与下个漏洞做比较
        tmp_name, tmp_risk, tmp_urls, tmp_solution = listHe[x][0],listHe[x][1], tmp_urls, listHe[x][3]
    # #最后一个漏洞无法比较，要单独输出。
    return new_list 

 
