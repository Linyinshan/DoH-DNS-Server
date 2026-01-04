# DoH-DNS-Server
一个基于 Java 开发的高性能、可配置的 DNS over HTTPS (DoH) 代理服务器。该项目旨在提供安全、隐私保护的 DNS 解析服务 支持多种高级功能，包括代理支持、域名过滤、本地 hosts 文件解析等</br>
Windows系统记得关闭DNS智能优化（组策略>>计算机配置>>管理模板>>网络>>DNS客户端>>禁用智能多宿主名称解析：已启用）</br>
</br>
启动方式</br>
java -jar doh-dns-server.jar</br>
</br>
参数说明</br>
-p, --port 端口    监听端口（默认: 53 或 config.ini中的设置）</br>
--doh URL         DoH服务器地址（可选，默认使用内置服务器或config.ini设置）</br>
--autoswitch-off  禁用DoH服务器自动切换功能（默认开启或根据config.ini设置）</br>
-h, --help        显示帮助信息</br>
</br>
示例</br>
java -jar doh-dns-server.jar -p 53</br>
java -jar doh-dns-server.jar --doh https://dns.google/dns-query</br>
java -jar doh-dns-server.jar --autoswitch-off</br>
java -jar doh-dns-server.jar -p 5353 --doh https://cloudflare-dns.com/dns-query</br>
</br>
</br>
【说明】</br>
·内置DoH服务器3个-支持修改</br>
腾讯：https://doh.pub/dns-query</br>
阿里：https://dns.alidns.com/dns-quer</br>
360：https://doh.360.cn/dns-query</br>
·DoH服务器支持自动切换-支持修改</br>
·可以自定义解析（Host.txt文件）</br>
·可以自定义屏蔽域名（BanDomain.txt文件）</br>
·支持socks代理以及代理认证</br>
·可使用config.ini文件进行修改配置</br>
首次启动后自动生成默认配置</br>
命令行将参数覆盖config.ini参数</br>
</br>
</br>
【声明】</br>
该项目支持二次开发以及用于商业用途，商业用途请保留原作github链接，二次开发开源项目或商业项目如需添加友情链接可联系邮箱linyins@qq.com，修改意见一样联系该邮箱</br>
