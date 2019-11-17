1、安装3.7.5，微软office。安装python时注意把“python添加到path” 选项勾上。（之前有装python2.7注意并存事项）
2、cmd进入vulnReport目录，输入 pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
3、输入python main.py启动（可以自己做bat 一键启动，如python D:\vulnReport\main.py）
4、有gen_py 错误，在删除目录C:\Users\administrator\AppData\Local\Temp\gen_py\3.7中的缓存文件夹