#-*-coding:utf-8 -*-
import zipfile
from bs4 import BeautifulSoup as bs
import re

def zhengli(fileName,info_flag):
    print(info_flag)
    html = ''
    vuln_hosts, vuln_solution = '', ''
    #(?isu)意思是匹配后面的中文
    table_re = re.compile("(?isu)<table[^>]*>(.*?)</table>")
    tr_re = re.compile("(?isu)<tr[^>]*>(.*?)</tr>")
    div_re = re.compile("(?isu)<div[^>]*>(.*?)</div>")
    
    #打开zip
    with zipfile.ZipFile(fileName, 'r') as z:
        f = z.read('Report/files/Report_main.html')
        vuln_list = []
        html = bs(f, "html.parser")
        #section_12_content 为第六章漏洞章节，如果启明更改了模板，后续的也要更改
        vuln_tabls = str(html.find(id="section_12_content"))
        #查找所有的table
        for table in table_re.findall(vuln_tabls):
            tmp_list = []
            #查找table里的tr
            for tr in tr_re.findall(table):
                #查找dr里的div，这里没有记录cve编号，如果要记录，则还要查找div里的a标签
                for div in div_re.findall(tr):
                    div_1 = div.strip().replace('<br>','').replace('</br>','')
                    div_2 = div_1.replace('\n', '').replace('\t', '')
                    tmp_list.append(div_2)
            #根据item得到下标号，为了正确显示某些低危漏洞没有修补建议，写成参考网址的情况
            for i, item in enumerate(tmp_list):
                if '存在主机' == item:
                    vuln_hosts = tmp_list[i+1]
                elif '修补建议' == item:
                    if tmp_list[i+1] != '参考网址':
                        vuln_solution = tmp_list[i+1]
                    else:
                        vuln_solution = ''
                else:
                    pass
            #判断是否输出 消息级别漏洞
            if tmp_list[8] == '信息' and not info_flag:
                continue
            # 2为漏洞名称，8为风险
            vuln_list.append([tmp_list[2], tmp_list[8], vuln_hosts, vuln_solution])
            tmp_list.clear()


        for x in vuln_list:
            #去除漏洞名称前面的数字，如【1】检测到远程主机存在vpasswd.cgi 变为 检测到远程主机存在vpasswd.cgi
            #正则，\d代表数字，+ 为至少一个，可替换为 .*?
            x[0] = re.sub('【\d+】', '', x[0])
            #去除“高风险”中的风险，变成“高”
            if '危险' in x[1]:
                x[1] = x[1].replace('危险', '')
            elif "信息" in x[1]:
                x[1] = x[1].replace('信息', '低')
            else:
                pass
                

        # z主机IP 为模板中的字段，需传输
        return ("主机IP", vuln_list)





 
