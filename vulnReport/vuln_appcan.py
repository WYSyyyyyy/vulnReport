# -*- coding=utf-8 -*-
 
from bs4 import BeautifulSoup as bs

#appscan 漏洞整理主函数
def zhengli(fileName, info_flag):


    appscan_list = []
    #打开漏洞文件,文件编码为gbk，这里要指定utf-8
    with open(fileName, 'r', encoding='utf-8') as f:
        
        content = bs(f, "html.parser")
        #查找所有的DIV
        vuln_list = content.find_all("div", "issueHeader")
        for html in vuln_list:
            tmp_list = []
            for div in html.select('div'):
                #得到DIV内容并去换行 制表符等符号
                tmp_list.append(div.get_text().replace('\n', '').replace('\t', ''))
            #如果是参考,结合flag 是否输出为低危漏洞
            if '参考' in tmp_list: 
                #如果 true，则把消息变低，false 则退出本次循环，不加入list中
                if info_flag:
                    tmp_list[3] = '低'
                else:
                    continue
            #根据html中显示，0为漏洞名称，3为漏洞风险值，9为URL，10为实体参数（9和10合并在一起输出），21为解决方案
            appscan_list.append([tmp_list[0], tmp_list[3], tmp_list[9] + ' ' + tmp_list[10], tmp_list[21]])
            #清空list，这样每次就能使用上一行代码
            tmp_list.clear()

        #合并漏洞的URL
        new_list = hebing_url(appscan_list)
        return ("URL地址", new_list)

def hebing_url(listHe):
    # text2.insert('end', "合并IP中……\n")
    # text2.update()
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
    

 
 