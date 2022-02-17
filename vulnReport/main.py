# -*-coding: utf-8 -*-

import tkinter as tk
import tkinter.filedialog as tkf
import os
import time
# import googletranslater
# import baiduTranslater
import vuln_nessus
import vuln_venusHost
import vuln_appcan
import vuln_awvs
import win32com.client as win32
from docx import Document
from docxcompose.composer import Composer 
from mailmerge import MailMerge

def first():
    #参考了以下大佬的程序或博客,表示感谢。
    #vuln_nessus HTML部分：https://github.com/Bypass007/Nessus_to_report
    #vuln_venusHost.py  https://blog.csdn.net/u010984277/article/details/53695356
    #vuln_awvs.py  https://www.freebuf.com/column/173394.html
    #vuln_appscan 这个找不到了，参考的不多
    #googletranslater.py 这个也找不到了，参考网上不知名大佬的

    #有问题或者建议可以联系我，邮箱：3115211094@qq.com

    pass


def selectFile1():
    #清除text1和result_text的文本内容
    text1.delete('1.0', 'end')
    result_text.delete('1.0', 'end')
    #显示文件名
    text1.insert('1.0', getFileName())


def selectFile2():
    #清除text2和result_text的文本内容
    text2.delete('1.0', 'end')
    result_text.delete('1.0', 'end')
    #显示文件名
    text2.insert('1.0', getFileName())


def selectFile3():
    #清除text3和result_text的文本内容
    text3.delete('1.0', 'end')
    result_text.delete('1.0', 'end')
    #显示文件名
    text3.insert('1.0', getFileName())


def selectFile4():
    #清除text4和result_text的文本内容
    text4.delete('1.0', 'end')
    result_text.delete('1.0', 'end')
    #显示文件名
    text4.insert('1.0', getFileName())

def getFileName():
    try:
        #因为按钮链接的函数不能有参数，所以需要全局变量file来接收打开的文件名
        global file
        file = str(tkf.askopenfilename())
        if file != '':
            return file
        else:
            return '无此文件。'
    except Exception as e:
        print("读取文件失败")
        print(e)

def getDestFileName(file1):
    #得到文件名和后缀
    (filename,extensionName) = os.path.splitext(file1)

    #生成目标文件名
    destFileName = filename + '漏洞整理.docx'
    destFileName = destFileName.replace(' ','_')
    return destFileName

#Nessus 漏洞整理函数
def zhengli_nessus():
    start_time = time.time()
    #提示信息
    result_text.insert('end',"开始整理中…… \n")
    result_text.update()

    (destF, extenN) = os.path.splitext(file)
    destFileName = destF + '漏洞整理.docx'
    destFileName = destFileName.replace(' ','_')

    if extenN == '.csv':

        #nessus 整理开始
        (category, nessus_list) = vuln_nessus.zhengli_csv(file, info_flag)
    elif extenN == '.html':
        #nessus 整理开始
        (category, nessus_list) = vuln_nessus.zhengli_html(file, info_flag)
    else:
        result_text.insert('end',"格式错误!\n")
        result_text.update()
        

    #提示信息
    result_text.insert('end',"写入报告中…… \n")
    result_text.update()
    #nessus开始写入
    write2docx(category, nessus_list, destFileName)
    # #提示信息
    # result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
    # result_text.update()
    consume_time = time.time() - start_time
    #提示信息
    result_text.insert('end',"耗时时间为："+str(consume_time) + '\n')
    result_text.update()

#天境6.0 整理函数
def zhengli_venus():
    start_time = time.time()
    #提示信息
    result_text.insert('end',"开始整理中…… \n")
    result_text.update()
    #天境6.0 整理开始
    (category, venus_list) = vuln_venusHost.zhengli(file, info_flag)
    #提示信息
    result_text.insert('end',"写入报告中…… \n")
    result_text.update()
    #天境6.0 写入word
    write2docx(category, venus_list, getDestFileName(file))
    
    consume_time = time.time() - start_time
    #提示信息
    result_text.insert('end',"耗时时间为："+str(consume_time) + '\n')
    result_text.update()


#APPScan 整理函数
def zhengli_appscan():
    start_time = time.time()
    #提示信息
    result_text.insert('end',"开始整理中…… \n")
    result_text.update()
    #appscan 整理开始
    (category, venus_list) = vuln_appcan.zhengli(file, info_flag)
    #提示信息
    result_text.insert('end',"写入报告中…… \n")
    result_text.update()
    #appscan写入
    write2docx(category, venus_list, getDestFileName(file))
    # #提示信息
    # result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
    # result_text.update()
    consume_time = time.time() - start_time
    #提示信息
    result_text.insert('end',"耗时时间为："+str(consume_time) + '\n')
    result_text.update()


#AWVS 整理函数
def zhengli_awvs():
    start_time = time.time()
    #提示信息
    result_text.insert('end',"开始整理中,AWVS涉及到翻译，请耐心等待…… \n")
    result_text.update()
    #awvs整理开始
    (category, venus_list) = vuln_awvs.zhengli(file, info_flag)
    #提示信息
    result_text.insert('end',"写入报告中…… \n")
    result_text.update()
    #awvs 写入
    write2docx(category, venus_list, getDestFileName(file))
    # #提示信息
    # result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
    # result_text.update()
    consume_time = time.time() - start_time
    #提示信息
    result_text.insert('end',"耗时时间为："+str(consume_time) + '\n')
    result_text.update()

#Burp Suite 整理函数
def zhengli_burp():
    start_time = time.time()
    #提示信息
    result_text.insert('end',"开始整理中,Burp Suite涉及到翻译，请耐心等待…… \n")
    result_text.update()
    #burp整理开始
    venus_list = vuln_burp.zhengli(file, info_flag)
    #提示信息
    result_text.insert('end',"写入报告中…… \n")
    result_text.update()
    #burp 写入
    write2docx('URL地址', venus_list, getDestFileName(file))
    # #提示信息
    # result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
    # result_text.update()
    consume_time = time.time() - start_time
    #提示信息
    result_text.insert('end',"耗时时间为："+str(consume_time) + '\n')
    result_text.update()



def write2docx(name, vulns_list, destFile):
    #得到当前main.py文件的路径，以便放 生成的模板文件
    pwd = os.getcwd()

    #漏洞模板文件，最上面的换行不要删除
    template_file = pwd + '\\vuln_template.docx'
    name_list = []
    count = 0
    #循环生成每个漏洞文件
    for vuln in vulns_list:
        count += 1
        #读取模板文件
        template = MailMerge(template_file)
        #写入指定的字段，这里的字段和模板文件中设置的字段对应
        template.merge(num = str(count), vuln_name = vuln[0], vuln_risk = vuln[1], vuln_category = name, vuln_detail = vuln[2], vuln_solution = vuln[3])
        template.write("tmpDocx\\test-{}.docx".format(count))

        name_list.append(pwd + "\\tmpDocx\\test-{}.docx".format(count))

    # print('写入时的文件名：'+destFile)
    #如果destfile存在则删除
    if os.path.exists(destFile):
        os.remove(destFile)

        #这个速度慢，而且需要经常清理缓存，且打开的word会被关闭，没有安装office不能用
        # mergeDocx_win32(destFile, name_list)
        #这个速度保守估计快4倍左右，一切正常
        if len(name_list) > 0:
            mergeDocx_pyDocx(destFile,name_list)
            #提示信息
            result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
            result_text.update()
        else:
            print("该文件无风险漏洞！")
            result_text.insert('end',"该文件无风险漏洞。 \n")
            result_text.update()
    else:
        # mergeDocx_win32(destFile, name_list)
        if len(name_list) > 0:
            mergeDocx_pyDocx(destFile,name_list)
            #提示信息
            result_text.insert('end',"写入word成功，请到原漏洞文件目录下查看。 \n")
            result_text.update()
        else:
            print("该文件无风险漏洞！")
            result_text.insert('end',"该文件无风险漏洞。 \n")
            result_text.update()

    #如果生成文件，则打开并替换空行
    if os.path.exists(destFile):
        replaceSpace(destFile)


def mergeDocx_win32(destFileName,file_list):
    #系统的word程序，没有安装则会报错不能使用
    word = win32.gencache.EnsureDispatch('Word.Application')
    #word窗口隐形
    word.Visible = False
    output_file = word.Documents.Add()
    #win32 这个合并是倒序的，在这里要反转
    file_list.reverse()
    for name in file_list:
        #循环合并
        output_file.Application.Selection.Range.InsertFile(name)
        #删除test文件
        os.remove(name)
    output_file.SaveAs(destFileName)


def mergeDocx_pyDocx(destFileName,file_list):
    number = len(file_list)
    
    master = Document(file_list[0])

    docx_composer = Composer(master)

    for x in range(1,number):
        docx_tmp = Document(file_list[x])
        docx_composer.append(docx_tmp)
    docx_composer.save(destFileName)
    
        


def replaceSpace(destFileName):
    # print('RP中的文件名：'+destFileName)
    word = win32.DispatchEx('Word.Application')
    #word窗口隐形
    word.Visible = False
    word.DisplayAlerts = 0
    doc = word.Documents.Open(destFileName)
    #doc_range = doc.Range()
    selection = word.Selection

    #这里开始替换空格
    Replace('^p', '', selection, 2)

    #保存
    doc.Save()

    #退出
    doc.Close()
    word.Quit()


#替换文档中多余的空行
def Replace(oldStr, newStr, selection, replaceMode):

    try:
        #word 宏中对应的脚本
        '''
        Selection.Find.ClearFormatting
        Selection.Find.Replacement.ClearFormatting
        With Selection.Find
            .Text = "xxx单位"
            .Replacement.Text = "广州医科大学"
            .Forward = True
            .Wrap = wdFindContinue
            .Format = False
            .MatchCase = False
            .MatchWholeWord = False
            .MatchByte = True
            .MatchWildcards = False
            .MatchSoundsLike = False
            .MatchAllWordForms = False
        End With
        Selection.Find.Execute Replace:=wdReplaceAll
        '''

        #设置替换
        #execute函数格式为(FindText, MatchCase, MatchWholeWord, MatchWildcards, MatchSoundsLike, MatchAllWordForms, Forward, Wrap, Format, ReplaceText, Replace)
        #replace 模式为wdReplaceNone，wdReplaceOne，wdReplaceAll 对应为0,1,2

        #设置查找的文本格式为  无格式
        selection.Find.ClearFormatting()
        #设置替换的文本格式为  无格式
        selection.Find.Replacement.ClearFormatting()
        #返回Boolean，成功为True
        selection.Find.Execute(oldStr, False, False, False, False, False, True, 1, False, newStr, replaceMode)

    except Exception as e:
        print('出错了:' + str(e))



def checkBT_click():
    global info_flag
    info_flag = not info_flag
    

    


if __name__ == "__main__":
    root = tk.Tk()
    root.title('漏洞整理工具V1.1  Powered By WY. @2019.11')

    file = ''

    #************
    #nessus 
    lb1 = tk.Label(root, text='Nessus CSV、HTML文件：')
    lb1.grid(row=0, column=0)

    text1 = tk.Text(root, width=80, height=1)
    
    text1.grid(row=0, column=1)
    text1.mark_set('here','1.0')
    b1 = tk.Button(root, text='请选择文件', command=selectFile1)
    b2 = tk.Button(root, text='整理', command=zhengli_nessus)
    b1.grid(row=0, column=2)
    b2.grid(row=0, column=3)
    #************************************************

    #天境6.0 压缩包
    lb2 = tk.Label(root, text='天镜6.0 压缩包：')
    lb2.grid(row=1, column=0)
    text2 = tk.Text(root, width=80, height=1)
    
    text2.grid(row=1, column=1)
    text2.mark_set('here','1.0')
    b3 = tk.Button(root, text='请选择文件', command=selectFile2)
    b4 = tk.Button(root, text='整理', command=zhengli_venus)
    b3.grid(row=1, column=2)
    b4.grid(row=1, column=3)
    #*************************************************

    #APPScan
    lb3 = tk.Label(root, text='APPScan的HTML文件：')
    lb3.grid(row=2, column=0)
    text3 = tk.Text(root, width=80, height=1)
    
    text3.grid(row=2, column=1)
    text3.mark_set('here','1.0')
    b5 = tk.Button(root, text='请选择文件', command=selectFile3)
    b6 = tk.Button(root, text='整理', command=zhengli_appscan)
    b5.grid(row=2, column=2)
    b6.grid(row=2, column=3)
    #**************************************************

    #AWVS
    lb4 = tk.Label(root, text='AWVS的HTML文件：')
    lb4.grid(row=3, column=0)
    text4 = tk.Text(root, width=80, height=1)
    
    text4.grid(row=3, column=1)
    text4.mark_set('here','1.0')
    b7 = tk.Button(root, text='请选择文件', command=selectFile4)
    b8 = tk.Button(root, text='整理', command=zhengli_awvs)
    b7.grid(row=3, column=2)
    b8.grid(row=3, column=3)
    #**************************************************

     #Burp Suite
    lb5 = tk.Label(root, text='BurpSuite的HTML文件：')
    lb5.grid(row=4, column=0)
    text5 = tk.Text(root, width=80, height=1)
    
    text5.grid(row=4, column=1)
    text5.mark_set('here','1.0')
    b7 = tk.Button(root, text='请选择文件', command=selectFile4)
    b8 = tk.Button(root, text='整理', command=zhengli_burp)
    b7.grid(row=4, column=2)
    b8.grid(row=4, column=3)
    #**************************************************



    lb_text = tk.Label(root, text='结果输出：')
    lb_text.grid(row=5, column=0)

    result_text = tk.Text(root, width=80, height=7)
    result_text.grid(row=5,column=1)

    #全局 消息 级别漏洞
    info_flag = False
    lb_checkbt = tk.Checkbutton(root, text='是否输出\n消息级别\n漏洞?默认为否。', command=checkBT_click)
    lb_checkbt.grid(row=5, column=2)


    #使用说明
    lb_attention = tk.Label(root, text='使用说明：')
    lb_attention.grid(row=6, column=0)

    attention_text = tk.Text(root, width=80, height=7)
    attention_text.grid(row=6,column=1)
    #
    attention = '''模板文件不要改动！    
Nessus 文件为CSV或HTML(Custom Group Vulnerabilities By HOST)格式，目前支持版本6.x-8.x，其余未经过测试！
天境6.0 文件必须为压缩包ZIP格式！
APPScan 文件必须为HTML格式！
AWVS 漏洞文件只支持Affected Items模板的HTML格式！ '''

    attention_text.insert('end', attention)
    attention_text.update()

    
    root.mainloop()