一、安装说明：

	1、安装python 3.7.5，安装python时注意把“python添加到path” 选项勾上，装好之后在cmd中输入：python 后显示 python3.7.5。（之前有装python2.7注意并存事项）
	2、cmd进入vulnReport目录，输入 pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
	3、点击“漏洞整理.bat”后启动。（如果python默认是python2.7，则bat中需要更改为python3命令。如：python3 main.py）
	4、旧版使用win32 office，如有gen_py 错误，在目录C:\Users\administrator\AppData\Local\Temp\gen_py\3.7中 删除缓存文件夹


二、更新说明

#V1.1版本    20191117 
1、googletranslater.py  修改为新版URL，翻译更加智能；
2、main.py 加入“是否翻译 消息级别漏洞”选项；取消使用win32 word application，改用python-docx、docxcompose库，速度提升；
3、vuln_awvs.py 修正翻译错误问题；
4、vuln_nessus.py 修正写入和翻译错误问题；加入HTML格式整理；