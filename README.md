# DoH-DNS-Server
一个基于 Java 开发的高性能、可配置的 DNS over HTTPS (DoH) 代理服务器。该项目旨在提供安全、隐私保护的 DNS 解析服务 支持多种高级功能，包括代理支持、域名过滤、本地 hosts 文件解析等
Windows系统记得关闭DNS智能优化（组策略>>计算机配置>>管理模板>>网络>>DNS客户端>>禁用智能多宿主名称解析：已启用）

启动方式
java -jar doh-dns-server.jar

参数说明
-p, --port 端口    监听端口（默认: 53 或 config.ini中的设置）
--doh URL         DoH服务器地址（可选，默认使用内置服务器或config.ini设置）
--autoswitch-off  禁用DoH服务器自动切换功能（默认开启或根据config.ini设置）
-h, --help        显示帮助信息

示例
java -jar doh-dns-server.jar -p 53
java -jar doh-dns-server.jar --doh https://dns.google/dns-query
java -jar doh-dns-server.jar --autoswitch-off
java -jar doh-dns-server.jar -p 5353 --doh https://cloudflare-dns.com/dns-query


【说明】
·内置DoH服务器3个-支持修改
腾讯：https://doh.pub/dns-query
阿里：https://dns.alidns.com/dns-quer
360：https://doh.360.cn/dns-query
·DoH服务器支持自动切换-支持修改
·可以自定义解析（Host.txt文件）
·可以自定义屏蔽域名（BanDomain.txt文件）
·支持socks代理以及代理认证
·可使用config.ini文件进行修改配置
首次启动后自动生成默认配置
命令行将参数覆盖config.ini参数


【声明】
该项目支持二次开发用于商业用途，商业用途请保留原作github链接，二次开发开源项目或商业项目如需添加友情链接可联系邮箱linyins@qq.com
