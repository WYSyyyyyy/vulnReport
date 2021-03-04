# vulnReport
包括 Nessus、天境主机漏洞扫描6.0、APPscan 9.0、awvs10.5、burpsuite等漏洞报告的整理，从整理翻译写入word模板或Excel（写入Excel代码没有，但这个比word模板简单很多，网上搜一下改动一下代码即可）一条龙服务。

nessus
  支持csv及HTML格式的报告漏洞整理，漏洞提取->漏洞主机合并->查找漏洞库或翻译（翻译后写入漏洞）->写入word漏洞模板->输出漏洞文档
  
其他的差不多是一样。有些少了翻译过程而已。

仅供个人学习使用。

一、安装说明：

	1、安装python 3.7.5，安装python时注意把“python添加到path” 选项勾上，装好之后在cmd中输入：python 后显示 python3.7.5。（之前有装python2.7注意并存事项）
	2、cmd进入vulnReport目录，输入 pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
	3、点击“漏洞整理.bat”后启动。（如果python默认是python2.7，则bat中需要更改为python3命令。如：python3 main.py）
	4、如有使用上的问题，请联系3115211094@qq.com。


