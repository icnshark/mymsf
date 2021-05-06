学习流程

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/msf0.png)

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/msf1.png)

其实主要是学习msf模块的开发，因为我太菜了。

msf提供了一个框架（api）来加载各种模块。

msf基础知识：

- 渗透模块（exploit）
- 攻击载荷模块（payload）
- 辅助模块（auxiliary）
- 编码器模块（encoder）
- Meterpreter

命令：

- use [Auxiliary/Exploit/Payload/Encoder]#选择一个指定的模块并使其开始工作
- show [exploits/payloads/encoder/auxiliary/options]#显示可用的特定功能的模块
- set [options/payload]#给某个特定对象赋值
- setg [options/payload]#给某个对象赋值的同时设定作用域为全局，在模块进行切换的时候，该对象的值不会被改变
- run#在设置一个辅助模块需要的所有选项之后，启动该辅助模块
- exploit#启动一个渗透模块
- back#取消当前选择的模块并且退回到上一级命令窗口
- info#列出相关模块的信息
- search#搜索符合条件的特定模块
- check#检查某个特定目标是否易受攻击
- sessions#列出当前可用的会话

初始化数据库 msfdb init

新建工作区 workspace -a mymsf

查看数据库服务 services