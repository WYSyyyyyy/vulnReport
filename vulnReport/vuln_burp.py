# -*- coding:utf8 -*-

from os import replace
from bs4 import BeautifulSoup as bs
# import googletranslater
import baiduTranslater
import re

def zhengli(fileName, info_flag):
    

    #思路：获取所有的<span class="BODH0"(不用<p class='TOCH0'),得到漏洞名字，find_next span class_='TEXT'得到所有url，大于5个取5个
    #再find_next h2 text='Issue remediation' 的前一个是 Issue remediation，得到漏洞修复建议
    #找到 summary_table ，类型和awvs 及APPscan有点相似


    with open(fileName, 'r', encoding='utf-8') as f:
        content = bs(f, "html.parser")
        #SQL注入有遇到Issue remediation 为Remediation background的问题，应该是burp自身的原因
        # content.replace('Remediation background', 'Issue remediation')
        # print('content的类型是'+str(type(content)))

        # '''
        #找到<span class="BODH0">中标签a的值
        #应用系统的根地址 
        host = ''
        #存放的漏洞信息，为漏洞名字、漏洞风险等级、漏洞url、漏洞修复建议
        vulnBurp = []
        #找到所有<span class="BODH0">,为漏洞文件名的标签。并以此为基点，向下寻找第一个符合情况的标签，包括risk、url、solution
        names = content.find_all('span', class_='BODH0')
        for name in names:
            #初始化缓冲输出为空
            urlstr = ''
            vulnName = ''
            vulnRisk = ''
            vulnURLs = ''
            vulnSolution = ''

            #得到漏洞名称
            vulnName = name.find('a').text
            #找到漏洞urls
            urls = name.find_next('span', class_='TEXT')
            #找到详细问题的table，里面有risk 和 host
            table = name.find_next('table', class_='summary_table').get_text().split('\n')

            #得到漏洞修复建议
            # vulnSolution = name.find_next('h2', text='Issue remediation').find_next('span').get_text()
            vulnSolution = name.find_next('h2', text=re.compile(r'.*?emediation.*?')).find_next('span').get_text()
            #根据值的规律，得到第五个字段为风险等级，第13个字段为host名字
            vulnRisk = table[4]
            if vulnRisk == 'Information':
                #info_flag 传进来是false，为不输出消息漏洞。负负得正
                # if info_flag:
                #     pass
                # else:
                #     break
                if not info_flag:
                    break
            host = table[12]
            #此处设置url只取5个值及以下
            i = 5
            for url in urls.select('li'):
                #退出本层循环
                if i < 1:
                    break
                #得到的url缺失host头，拼接并追加\n
                urlstr += host + url.get_text() + '\n'
                i -= 1
            if urlstr:
                vulnURLs = urlstr[:-2]
            else:
                #如果没有漏洞url，则为应用系统根地址
                vulnURLs = host
            #单个漏洞的全部示例
            vulnBurp.append([vulnName, vulnRisk, vulnURLs, "".join([s for s in vulnSolution.splitlines(True) if s.strip()])])
        # print(vulnBurp)
            
        #翻译并返回数据
        # print(info_flag)
        for x in vulnBurp:
            if x[1] == 'High':
                x[1] = '高'
            elif x[1] == 'Medium':
                x[1] = '中'
            elif x[1] == 'Low':
                x[1] = '低'
            elif x[1] == 'Information':
                x[1] = '低'
                
            
        
        for x in vulnBurp:
            # x[0] = googletranslater.googleTrans(x[0])
            # x[3] = googletranslater.googleTrans(x[3])
            # x[3] = googletranslater.googleTrans("".join([s for s in x[3].splitlines(True) if s.strip()]))
            #20211028 add
            #谷歌翻译改了不能用了，用百度翻译
            x[0] = baiduTranslater.baiduTrans(x[0])
            x[3] = baiduTranslater.baiduTrans(x[3])
        
        return vulnBurp
        
        


