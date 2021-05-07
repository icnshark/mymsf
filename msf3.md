早上逃课美滋滋：）

昨天学习分析了msf的第一个模块`http_version`

今天来编写一个

##### FTP服务识别模块

------

伪代码

```
连接ftp
获取banner
保存到数据库
```

基本代码

```ruby
require 'msf/core'	#引入core库
class Metasploit3 < Msf::Auxiliary	#定义为辅助模块
  include Msf::Exploit::Remote::Ftp 
  include Msf::Auxiliary::Scanner 
  include Msf::Auxiliary::Report	#包含库文件
  def initialize 
  super( 
  'Name' => 'FTP Version Scanner Customized Module', 
  'Description' => 'Detect FTP Version from the Target', 
  'Author' => 'Nipun Jaswal', 
  'License' => MSF_LICENSE 
  )	#info
  register_options( 
  [ 
  Opt::RPORT(21),	#ftp port
  ], self.class) 
end
```

|         引入语句         |               路 径                |                            用 途                             |
| :----------------------: | :--------------------------------: | :----------------------------------------------------------: |
| Msf:Exploit::Remote::Ftp |    /lib/msf/core/exploit/ftp.rb    | 包含了所有FTP操作相关的方法，比如建立FTP连接、FTP服务登录、发送FTP命令等 |
| Msf::Auxiliary::Scanner  | /lib/msf/core/auxiliary/scanner.rb | 包含了各种扫描模块要使用的函数，提供了很多方法，例如模块运行、初始化以及进度扫描等 |
|  Msf::Auxiliary::Report  | /lib/msf/core/auxiliary/report.rb  | 包含了所有报告函数，这些函数可以将正在运行的模块中的数据存储到数据库中 |

核心代码

```ruby
def run_host(target_host) 
  connect(true, false)	#/lib/msf/core/exploit/remote/ftp.rb 会返回banner到banner变量
   if(banner)	#ture则代表连接成功
  	print_status("#{rhost} is running #{banner}") 
  	report_service(:host => rhost, :port => rport, :name => "ftp", :info => 
banner)	#存入数据库
  	end 
  	disconnect	#断开ftp
end
```

###### connect

```ruby
	#
	# This method establishes an FTP connection to host and port specified by
	#此方法建立与主机和指定端口的FTP连接
	# the 'rhost' and 'rport' methods. After connecting, the banner
	#'rhost'和'rport'方法。 连接后，横幅
	# message is read in and stored in the 'banner' attribute.
	#消息已读入并存储在“横幅”属性中。
	#
	def connect(global = true, verbose = nil)
		verbose ||= datastore['FTPDEBUG']
		verbose ||= datastore['VERBOSE']

        print_status("Connecting to FTP server #{rhost}:#{rport}...") if verbose

        fd = super(global)

        # Wait for a banner to arrive...
		#等待横幅到达...
        self.banner = recv_ftp_resp(fd)

        print_status("Connected to target FTP server.") if verbose

        # Return the file descriptor to the caller
        #将文件描述符返回给调用者
		fd
	end
```

需要向connect函数提供两个参数：true和false。参数true定义了全局参数的使用，而false定义关闭模块的详细功能。

###### msf6 code

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'	#引入core库

class Metasploit3 < Msf::Auxiliary	#定义为辅助模块
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report	#包含库文件
  def initialize
    super(
      'Name' => 'FTP Version Scanner Customized Module',
      'Description' => 'Detect FTP Version from the Target',
      'Author' => 'Nipun Jaswal',
      'License' => MSF_LICENSE
    )	#info
    
    register_options(
      [
        Opt::RPORT(21),	#ftp port
      ])
  end
  def run_host(target_host)
      connect(true, false)	#/lib/msf/core/exploit/remote/ftp.rb 会返回banner到banner变量
    if(banner)	#ture则代表连接成功
    print_status("#{rhost} is running #{banner}")
    report_service(:host => rhost, :port => rport, :name => "ftp", :info =>banner)	#存入数据库
    end
    disconnect	#断开ftp
  end
end
```

run

```ruby
msf6 auxiliary(scanner/ftp/ftp_scan_servies) > run

[*] 173.254.88.30:21      - 173.254.88.30 is running 220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 3 of 150 allowed.
220-Local time is now 00:37. Server port: 21.
220-IPv6 connections are also welcome on this server.
220 You will be disconnected after 15 minutes of inactivity.

[*] 173.254.88.30:21      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

###### loadpath文件结构

```shell
┌──(dayu㉿kali)-[~/桌面]
└─$ tree mymsfmodules 
mymsfmodules
└── modules
    └── auxiliary
        └── scanner
            └── ftp
                └── ftp_scan_servies.rb
```































