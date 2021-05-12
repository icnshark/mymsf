今天是5.12已经5天没更新了，有事情耽误了一下。周末休息了2天，然后kali upgrade还崩了，懒得修了，就重装了Windows10。。。

今天开始就不看书了，开始看msf的自带模块，先慢慢看着吧，感觉比写golang有趣

说说现在我的配置环境

```
主系统	windows10
虚拟机	kali
IDE	rubymine
```

现在我ide就是一个代码补全：）配过dockers环境，失败了，我还是手动复制文件到kali上面去跑吧

之前说了现在研究msf模块，就从msf的auxiliary/scanner/http开始吧

先来了解了解msf http的api

![](https://raw.githubusercontent.com/icnshark/my-msf-photo/main/20210512160917.png)

太多了，随便选一个

就backup_file.rb吧，~~就这个单词全部都认识~~

~~我真不会ruby啊~~，先想一下大体逻辑，原理，以及自己怎么去实现它，看名字可以看出这是一个查找备份文件的东西，实现的话非常简单，得有2个fuzz的地方，文件名和文件后缀，然后爆破即可

想看看模块options

```shell
msf6 auxiliary(scanner/http/backup_file) > options 

Module options (auxiliary/scanner/http/backup_file):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /index.asp       yes       The path/file to identify backups
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port
                                       ][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts fi
                                       le with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


```

直接看代码

```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanFile
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Backup File Scanner',
      'Description'	=> %q{
        This module identifies the existence of possible copies
        of a specific file in a given path.
      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path/file to identify backups", '/index.asp'])
      ])

  end
  #以上不用看系列
  def run_host(ip)
    bakextensions = [
      '.backup',
      '.bak',
      '.copy',
      '.copia',
      '.old',
      '.orig',
      '.temp',
      '.txt',
      '~'
    ]
    #定义了一个后缀名的list
    bakextensions.each do |ext| #list迭代器，后缀名循环。
      file = normalize_uri(datastore['PATH'])+ext #PATH，然后加上后缀名。接着往下看看
      check_for_file(file, ip)  #看看函数定义
    end
    if datastore['PATH'] =~ %r#(.*)(/.+$)#  #正则表达式，匹配PATH
      file = $1 + $2.sub('/', '/.') + '.swp'  #如果匹配到了则会扫描一下swp文件
      check_for_file(file, ip)
    end
  end
  def check_for_file(file, ip)
    begin
      res = send_request_cgi({	#个人理解为一个http的建立链接
          'uri'  		=>  file,
          'method'   	=> 'GET',
          'ctype'		=> 'text/plain'
          }, 20)

      if (res and res.code >= 200 and res.code < 300)	#判断响应码
        print_good("Found #{wmap_base_url}#{file}")

        report_web_vuln(
          :host	=> ip,
          :port	=> rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path	=> file,
          :method => 'GET',
          :pname  => "",
          :proof  => "Res code: #{res.code.to_s}",
          :risk   => 0,
          :confidence   => 100,
          :category     => 'file',
          :description  => 'Backup file found.',
          :name   => 'backup file'
        )

      else
        vprint_status("NOT Found #{wmap_base_url}#{file}")
        #To be removed or just displayed with verbose debugging.
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end


  end
end
```

###### normalize_uri(*strs) ⇒ Object

```ruby
  # 返回URI的修改版本：
  # 1.总是有一个开始斜杠
  # 2.删除所有双斜杠
  def normalize_uri(*strs)
    new_str = strs * "/"

    new_str = new_str.gsub!("//", "/") while new_str.index("//")

    # Makes sure there's a starting slash
    unless new_str.start_with?("/")
      new_str = '/' + new_str
    end

    new_str
  end
```

###### list.each

```shell
┌──(kali㉿kali)-[~/ruby]
└─$ cat test.rb 
list = [
  'a',
  'b',
  'c'
]

list.each do |p|
  puts p
end
                                                                                               
┌──(kali㉿kali)-[~/ruby]
└─$ ruby test.rb
a
b
c

```

###### send_request_cgi(opts = {}, timeout = 20, disconnect = true) ⇒ Object

```ruby
# File 'lib/msf/core/exploit/remote/http_client.rb', line 385

def send_request_cgi(opts = {}, timeout = 20, disconnect = true)
  if opts.has_key?('cookie')
    if opts['cookie'].is_a?(Msf::Exploit::Remote::HTTP::HttpCookieJar)
      cookie_jar.cleanup unless opts['expire_cookies'] == false
      opts.merge({ 'cookie' => opts['cookie'].cookies.join('; ') })
    else
      opts.merge({ 'cookie' => opts['cookie'].to_s })
    end
  elsif !cookie_jar.empty?
    cookie_jar.cleanup unless opts['expire_cookies'] == false
    opts = opts.merge({ 'cookie' => cookie_jar.cookies.join('; ') })
  end

  res = send_request_raw(opts.merge(cgi: true), timeout, disconnect)
  return unless res

  if opts['keep_cookies'] && res.headers['Set-Cookie'].present?
    cookie_jar.parse_and_merge(res.headers['Set-Cookie'], "http#{ssl ? 's' : ''}://#{vhost}:#{rport}")
  end

  res
end
```

连接到服务器，创建请求，发送请求，读取响应

如果在'cookie'键下的opts dict中传递了Msf :: Exploit :: Remote :: HTTP :: HttpCookieJar实例，则表示CookieJar将用于请求中，而不是模块cookie_jar

将`opts`直接传递给Rex :: Proto :: Http :: Client＃request_cgi。 设置`opts`可以阻止cookie响应，以便在请求中重复使用。 服务器返回的Cookie将存储在cookie_jar中

expire_cookies将控制是否在任何传递的Msf :: Exploit :: Remote :: HTTP :: HttpCookieJar或客户端cookiejar上调用清除

###### report_web_vuln(opts) ⇒ Object

https://rapid7.github.io/metasploit-framework/api/Msf/DBManager/Web.html#report_web_vuln-instance_method

```
  def report_web_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_vuln(opts)
  end
```

保存到数据库。

运行结果

```shell
msf6 auxiliary(scanner/http/backup_file) > set PaTH /a/a.asp
PaTH => /a/a.asp
msf6 auxiliary(scanner/http/backup_file) > set rhosts 192.168.1.1
rhosts => 192.168.1.1
msf6 auxiliary(scanner/http/backup_file) > run

[+] Found http://192.168.1.1:80/a/a.asp.backup
[+] Found http://192.168.1.1:80/a/a.asp.bak
[+] Found http://192.168.1.1:80/a/a.asp.copy
[+] Found http://192.168.1.1:80/a/a.asp.copia
[+] Found http://192.168.1.1:80/a/a.asp.old
[+] Found http://192.168.1.1:80/a/a.asp.orig
[+] Found http://192.168.1.1:80/a/a.asp.temp
[+] Found http://192.168.1.1:80/a/a.asp.txt
[+] Found http://192.168.1.1:80/a/a.asp~
[+] Found http://192.168.1.1:80/a/.a.asp.swp #正则表达式匹配success
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

这个模块感觉不太完善，fuzz的点只有一个，而且参数太少。

```
www.test.com/fuzz.fuzz
```

