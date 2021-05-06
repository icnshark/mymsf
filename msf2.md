msf基础已经粗略写过，现在进入重点，msf模块开发。msf是ruby开发的，也可以用python等语言来编写模块但是是通过另一层来兼容的。为了避免麻烦我采用ruby来开发，直接现学ruby语法。编程语言只是工具而已，自己的思想才是灵魂。

。。。顺便看了看，边学边Google吧。

先来了解一下

------

##### msf体系结构

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/msf2.png)

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/msf3.png)

基础库文件：

- Ruby扩展（REX）	处理几乎所有的核心功能，如设置网络套接字、网络的连接、格式化和所有其他基本功能
- MSF核心	提供了基本的API和框架的实际核心
- MSF基础	对模块提供了友好的API

模块类型：

见msf1

------

##### msf文件结构

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/msf4.png)

目录：

- lib	Metasploit的核心和灵魂，包含了帮助我们建立MSF模块的全部重要库文件
- modules	包含Metasploit中的所有模块——从扫描模块到后渗透模块，每一个Metasploit中集成的模块都可以在这个目录中找到
- tools	包含了用于辅助渗透测试的命令行程序。从创造无用数据到查找JMP ESP地址的工具都可以在这里找到，所有有用的命令行程序都包含于此
- plugins	包含了所有用于扩展Metasploit功能的插件，例如OpenVAS、Nexpose、Nessus以及其他各种可以使用 load 命令载入的工具
- scripts	包含了Meterpreter和其他各种脚本

------

##### 库的布局

Metasploit的模块是由各种各样的函数构成的。这些函数包括各种基础库文件以及使用Ruby编写的通用程序。在使用这些函数之前，首先要知道这些函数是什么，如何使用这些函数，调用函数时需要传递多少个参数？更重要的是，这些函数的返回值会是什么？

见书

------

##### msf模块格式

```ruby
require 'msf/core'	#导入库文件
class MetasploitModule < Msf::Auxiliary	#定义这个类的类型(辅助模块)
 def initialize(info = {})	#默认构造方法
 super(update_info(info, 
 'Name' => 'Module name', 
 'Description' => %q{ 
 Say something that the user might want to know. 
 }, 
 'Author' => [ 'Name' ], 
 'License' => MSF_LICENSE 
 )) 
 end 
 def run	#主函数
 # Main function 
 end 
end
```

##### 分析已知模块

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary	#辅助模块

  # Exploit mixins should be called first	# 首先调用渗透mixins类
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last	# 接着是扫描器模块mixins类
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP Version Detection',
      'Description' => 'Display version information about each system.',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_wmap_options({	#WMAP模块的默认参数
        'OrderID' => 0,
        'Require' => {},
      })
  end

  # Fingerprint a single host
  def run_host(ip)	#/lib/msf/core/auxiliary/scanner.rb
    begin
      connect	#/lib/rex/proto/mqtt/client.rb
      res = send_request_raw({ 'uri' => '/', 'method' => 'GET' })	#连接到服务器，创建请求，发送请求，返回一个响应
      fp = http_fingerprint(:response => res)	#创建一个任意HTTP请求
      print_good("#{ip}:#{rport} #{fp}") if fp	#Ruby if 修饰符
      report_service(:host => rhost, :port => rport, :sname => (ssl ? 'https' : 'http'), :info => fp)	#服务的检测报告
    rescue ::Timeout::Error, ::Errno::EPIPE	#错误处理
    ensure	#后处理
      disconnect
    end
  end
end

```

|              语 句               |                 路 径                 |                            用 途                             |
| :------------------------------: | :-----------------------------------: | :----------------------------------------------------------: |
| Msf::Exploit::Remote::HttpClient | /lib/msf/core/exploit/http/client.rb  | 这个库文件提供了大量方法，例如连接到目标计算机、发送请求、切断与客户端的连接等 |
|  Msf::Auxiliary::WmapScanServer  | /lib/msf/core/auxiliary/wmapmodule.rb | WMAP是一款基于Metasploit的通用Web应用程序扫描框架，有助于完成Metasploit的Web渗透测试 |
|     Msf::Auxiliary::Scanner      |  /lib/msf/core/auxiliary/scanner.rb   | 这个文件包含了基于扫描模块的所有函数，提供了模块运行、模块初始化、扫描进度等各种方法 |

###### send_request_raw(opts = {}, timeout = 20, disconnect = false) ⇒ Object

```ruby
send_request_raw({ 'uri' => '/', 'method' => 'GET' })
# File 'lib/msf/core/exploit/remote/http_client.rb', line 320

def send_request_raw(opts = {}, timeout = 20, disconnect = false)
  if datastore['HttpClientTimeout'] && datastore['HttpClientTimeout'] > 0
    actual_timeout = datastore['HttpClientTimeout']
  else
    actual_timeout = opts[:timeout] || timeout
  end

  c = connect(opts)	#opts实际上传递给了connect
  r = opts[:cgi] ? c.request_cgi(opts) : c.request_raw(opts)
  ...
end
```

###### http_fingerprint(opts = {}) ⇒ String

- :response (Rex::Proto::Http::Packet)	任何send_ *方法的返回值
- :uri (String)	默认值：'/'-要生成指纹的请求的HTTP URI
- :method (String)	默认值：'GET'-在指纹请求中使用的HTTP方法
- :full (Boolean)	默认值：false —请求完整的HTTP指纹，而不仅仅是签名

###### report_service(opts = {}) ⇒ Object

服务的检测报告

```ruby
# File 'lib/msf/core/auxiliary/report.rb', line 165

def report_service(opts={})
  return if not db
  opts = {
      :workspace => myworkspace,
      :task => mytask
  }.merge(opts)
  framework.db.report_service(opts)
end
```



------

