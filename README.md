# Virus-Learning
感染PE文件的病毒学习过程
#### 学习技术：
1. 重定位
2. API函数地址的获取：
1）暴力搜内存中kernel32.dll基址
2）通过PEB获取kernel32.dll基址
3. 感染PE文件
4. 磁盘递归搜索技术
#### 主要功能：
感染桌面上所有的exe后缀文件，使之弹出MessageBox，并继续运行原有程序
#### 注意事项：
1. 需要修改Desktop和sPath的路径为自己的桌面路径
2. 如果感染开启了ASLR的文件只会执行感染代码而无法执行原程序，原因是OEP写入问题
3. 使用MASM编写，编译使用MASMPLUS
4. 使用暴力搜索内存寻找kernel32.dll基址的程序在WIN10上无法运行，因为WIN10有保护机制，会进入SEH
