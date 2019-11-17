#-*-coding:utf-8 -*-
import sqlite3
import googletranslater
import pandas as pd
from lxml import etree
import re


#翻译程序主入口
def zhengli_csv(srcFile, info_flag):
    
    #csv读取整合
    #预处理,读取csv数据文件
    csv_list = read_csv(srcFile, info_flag)
    #连接漏洞数据库
    conn = sqlite3.connect('nessus.db')
    conn.text_factory = str
    cursor = conn.cursor()
    # text = cursor.execute("select * from vuln where vuln_en='Anonymous FTP Enabled'")
    # for row in text:
    #     print(row)
    #新建list，存放在漏洞库中的数据及翻译后的数据
    # print(csv_list)
    new_list = csv_list
    j=0
    for i in csv_list:
        # print(i[0])
        result = cursor.execute("select * from nessus where pluginID=?", (int(i[0]),))
        #单纯用result的话，取其长度后，值就无法取出来了，所以要先fetchall
        result1 = result.fetchall()
        if len(list(result1)):
            for row in result1:
                new_list[j][1] = row[2]
                new_list[j][4] = row[4]
        else:
            #翻译并写入漏洞库
            new_list[j][1] = googletranslater.googleTrans(i[1])
            new_list[j][4] = googletranslater.googleTrans(i[4])
            conn.execute("insert into nessus values(?, ?, ?, ?, ?)", (int(i[0]), i[1], new_list[j][1], i[2], new_list[j][4]))


        j = j + 1
    
    #数据库中的数据有可能有不管怎样替换都会存在自动换行，在这里替换效果最好
    #write2docx中只有4个字段，无pluginID，所以这里要去掉
    nessus_list = []
    for x in new_list:
        x[1] = x[1].replace("\n", "")
        x[4] = x[4].replace("\n", "")
        nessus_list.append([x[1], x[2], x[3], x[4]])

    # write2csv(new_list, destFile)
    #提交插入
    conn.commit()
    return ("主机IP", nessus_list)

def zhengli_html(srcFile, info_flag):
    
    #csv读取整合
    #预处理,读取csv数据文件
    csv_list = read_html(srcFile, info_flag)
    #连接漏洞数据库
    conn = sqlite3.connect('nessus.db')
    conn.text_factory = str
    cursor = conn.cursor()
    # text = cursor.execute("select * from vuln where vuln_en='Anonymous FTP Enabled'")
    # for row in text:
    #     print(row)
    #新建list，存放在漏洞库中的数据及翻译后的数据
    # print(csv_list)
    # new_list = csv_list
    j=0
    for i in csv_list:
        tmp_en_name = i[1]
        result = cursor.execute("select * from nessus where pluginID=?", (int(i[0]),))
        #单纯用result的话，取其长度后，值就无法取出来了，所以要先fetchall
        result1 = result.fetchall()
        if len(list(result1)):
            for row in result1:
                # new_list[j][1] = row[2]
                # new_list[j][4] = row[4]
                i[1] = row[2]
                i[4] = row[4]
        else:
            #翻译并写入漏洞库
            # new_list[j][1] = googletranslater.googleTrans(i[1])
            # new_list[j][4] = googletranslater.googleTrans(i[4])
            # conn.execute("insert into nessus values(?, ?, ?, ?, ?)", (int(i[0]), i[1], new_list[j][1], i[2], new_list[j][4]))
            i[1] = googletranslater.googleTrans(i[1])
            i[4] = googletranslater.googleTrans(i[4])
            print(tmp_en_name)
            print('*************\n')
            print(i[1])
            conn.execute("insert into nessus values(?, ?, ?, ?, ?)", (int(i[0]), tmp_en_name, i[1], i[2], i[4]))


        j = j + 1
    
    #数据库中的数据有可能有不管怎样替换都会存在自动换行，在这里替换效果最好
    #write2docx中只有4个字段，无pluginID，所以这里要去掉
    nessus_list = []
    # for x in new_list:
    for x in csv_list:
        x[1] = x[1].replace("\n", "")
        x[4] = x[4].replace("\n", "")
        nessus_list.append([x[1], x[2], x[3], x[4]])

    # write2csv(new_list, destFile)
    #提交插入
    conn.commit()
    return ("主机IP", nessus_list)


#读取csv文件
def read_csv(csv_name, info_flag):
    #pandas中parse模块默认使用C engine，不支持中文。使用engine=‘python’解决不识别中文文件的问题

    #读取所需的内容，包括pluginID、risk、host、name和solution
    data_pluginID = pd.read_csv(filepath_or_buffer=csv_name,engine='python')["Plugin ID"].values
    data_name = pd.read_csv(filepath_or_buffer=csv_name,engine='python')["Name"].values
    data_risk = pd.read_csv(filepath_or_buffer=csv_name,engine='python')["Risk"].values
    data_host = pd.read_csv(filepath_or_buffer=csv_name,engine='python')["Host"].values
    data_solution = pd.read_csv(filepath_or_buffer=csv_name,engine='python')["Solution"].values


    #设置列表存储读取到的值
    #这里的思路和vuln_appscan是一样的。
    mylist, risk_high, risk_medium, risk_low = [],[],[],[]
    #得到漏洞数量
    lines = len(data_risk)

    #每行读取
    for i in range(0, lines-1):

        #不读取none、low级别
        # if data_risk[i] == "None" or data_risk[i] == "Info" :
        #     pass
        if data_risk[i] == "None" or data_risk[i] == "Info" and info_flag :
            # print(str(i)+data_risk[i])
            risk_low.append([data_pluginID[i], data_name[i], "低", data_host[i], data_solution[i]])
        #读取紧急级别
        elif data_risk[i] == "Critical" or data_risk[i] == "High":
            #risk_high.append([data_pluginID[i], data_name[i], data_risk[i], data_host[i], data_solution[i]])
            risk_high.append([data_pluginID[i], data_name[i], "高", data_host[i], data_solution[i]])


        # 读取中级别
        elif data_risk[i] == "Medium":
            #risk_medium.append([data_pluginID[i], data_name[i], data_risk[i], data_host[i], data_solution[i]])
            risk_medium.append([data_pluginID[i], data_name[i], "中", data_host[i], data_solution[i]])

        # 读取低级别
        else:
            #risk_low.append([data_pluginID[i], data_name[i], data_risk[i], data_host[i], data_solution[i]])
            risk_low.append([data_pluginID[i], data_name[i], "低", data_host[i], data_solution[i]])
    
    risk_high.sort(key=takeName)
    risk_medium.sort(key=takeName)
    risk_low.sort(key=takeName)

    mylist.extend(risk_high)
    mylist.extend(risk_medium)
    mylist.extend(risk_low)

    #创建新列表存放去重后的结果

    list1 = []
    for x in mylist:
        if x not in list1:
            list1.append(x)

    #合并IP
    new_list = hebing(list1)

    return new_list

def read_html(html_name, info_flag):
    pluginID, name, host, risk, solution = '', '', '', '', ''
    # nessus_html_lists = []
    mylist, risk_high, risk_medium, risk_low = [],[],[],[]
    html = etree.parse(html_name, etree.HTMLParser())

    #把pluginID与漏洞名称分离的正则
    sp =  re.compile('(.*?)-(.*?)$')   
    nessus_vulns = html.xpath('/html/body/div[1]/div[3]/div')

    for vuln in nessus_vulns:
        #找IP
        if "font-size: 22px; font-weight: bold; padding: 10px 0;" in str(etree.tostring(vuln)):
            host = vuln.text
        #漏洞
        elif "this.style.cursor" in str(etree.tostring(vuln)):
            result = htm_parse(vuln, info_flag)
            #返回的是((id,name),high)的形式
            (tmp, risk) = result
            #非空
            if tmp != '' and risk != '':
                p_n = sp.findall(tmp)
                (pluginID, name) = p_n[0]
        #找到漏洞下的container 找到漏洞细节及修复方案
        elif "container" in str(etree.tostring(vuln)):
            solution_div_list = vuln.xpath('./div[8]')
            solution = solution_div_list[0].text

            if risk == '高':
                risk_high.append([pluginID, name, risk, host, solution])
            elif risk == '中':
                risk_medium.append([pluginID, name, risk, host, solution])
            elif risk == '低':
                risk_low.append([pluginID, name, risk, host, solution])
            else:
                pass
        else:
            pass

    risk_high.sort(key=takeName)
    risk_medium.sort(key=takeName)
    risk_low.sort(key=takeName)

    mylist.extend(risk_high)
    mylist.extend(risk_medium)
    mylist.extend(risk_low)
    
    #合并IP
    new_list = hebing(mylist)

    return new_list


def htm_parse(l, info_flag): 
    info, risk = '',''     
    #危急级别
    if '#d43f3a' in str(etree.tostring(l)):
        (info, risk) = (l.text, "高")
    #高级别
    elif '#ee9336' in str(etree.tostring(l)):
        (info, risk) = (l.text, "高")
        # info=l.text + " - 高"
    #中级别
    elif '#fdc431' in str(etree.tostring(l)):
        (info, risk) = (l.text, "中")
        # info=l.text + " - 中"
    #低级别
    elif '#3fae49' in str(etree.tostring(l)):
        (info, risk) = (l.text, "低")
        # info=l.text + " - 低"          
    # elif '#0071b9' in str(etree.tostring(l)):
    #消息或None级别
    elif '#0071b9' in str(etree.tostring(l)) and info_flag:
        (info, risk) = (l.text, "低")
        # info=l.text + " - 低"
    
    
    return (info, risk)

#合并IP
def hebing(listHe):
    #获取列表长度
    listHe.append(["", "", "", "", ""])
    list_len = len(listHe)
    #设置临时变量，作为缓冲输出
    tmp_pluginID, tmp_name, tmp_risk, tmp_host, tmp_solution = listHe[0][0], listHe[0][1], listHe[0][2], listHe[0][3], listHe[0][4]
    # tmp_name, tmp_risk, tmp_host, tmp_solution = listHe[0][0], listHe[0][1], listHe[0][2], listHe[0][3]
    #接收列表
    new_list = []
    #循环获取每一个漏洞，这次比较完输出上个漏洞的情况。
    for x in range(list_len):
        #如果漏洞id一样，则合并IP
        if listHe[x][0] == tmp_pluginID:  #and listHe[x][1] != tmp_host
            #如果初始ip和第一项IP一样则pass，主要针对第一个漏洞情况
            if tmp_host != listHe[x][3]:

                tmp_host = tmp_host + "、" + listHe[x][3]
        #输出漏洞详情和设置新的tmp_host
        else:   # listHe[x][2] != tmp_name:  #and tmp_host1 != ""
            new_list.append([tmp_pluginID, tmp_name, tmp_risk, tmp_host, tmp_solution])
            tmp_host = listHe[x][3]
        #设置这次的漏洞与下个漏洞做比较
        tmp_pluginID, tmp_name, tmp_risk, tmp_host, tmp_solution = listHe[x][0], listHe[x][1], listHe[x][2], tmp_host, listHe[x][4]
    # #最后一个漏洞无法比较，要单独输出。
    return new_list


#取第2列作为排序标准
def takeName(elem):
    return elem[1]


    
  



# # 把翻译好的东西写入到excel中,备用
# def write2csv(Nlist,filename):
#     # 以危险级别排序
#     # Nlist.sort(key=takeThree)

#     #写入数据
#     with open(filename,'w',newline='') as f:
#         csv_writer = csv.writer(f, dialect='excel')
#         #写入标题
#         title = ['ID', 'name', 'risk', 'host', 'solution']
#         csv_writer.writerow(title)

#         for i in Nlist:
#             csv_writer.writerow(i)
#     # text2.insert('end', "写入数据成功。\n")
#     # text2.update()
#     print("写入完成")