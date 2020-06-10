
### 部署环境

系统:debian 9.5
测试方: 192.168.183.129
IDS: 192.168.183.130

### 安装依赖

client：
apt-get install -y ncrack nikto hping3 apache2-utils \ 
tcpreplay python-scapy python-feedparser python-cherrypy3 \
python-paramiko nmap vsftp

server:
apt-get install -y apache2 vsftp

### 修改配置
conf/config.cfg配置情况：

`
[CLIENT]
ipaddr                  = 192.168.183.130
iface                   = eth0 #IDS抓包网口
useproxy                = 0
proxyhost               =
proxyport               =
proxyuser               =
proxypass               =

[PATHS]
db                      = data/pytbull.db
urlpdf                  = https://github.com/sebastiendamaye/public/raw/master/infected/
pdfdir                  = pdf/malicious
pcapdir                 = pcap
tempfile                = /tmp/pytbull.tmp
#alertsfile              = /var/log/snort/alert
alertsfile              = /var/log/suricata/fast.log

[ENV]
sudo                    = /usr/bin/sudo
nmap                    = /usr/bin/nmap
nikto                   = /usr/bin/nikto
niktoconf               = nikto.conf
hping3                  = /usr/sbin/hping3
tcpreplay               = /usr/bin/tcpreplay
ab                      = /usr/bin/ab
ping                    = /bin/ping
ncrack                  = /usr/bin/ncrack
ncrackusers             = data/ncrack-users.txt
ncrackpasswords         = data/ncrack-passwords.txt
localhost               = 127.0.0.1

[SSH]
port                    = 22 #定义ssh端口

[FTP]
ftpproto                = sftp
ftpport                 = 22
ftpuser                 = pytbull
ftppasswd               = pytbull

[TIMING]
sleepbeforegetalerts    = 2
sleepbeforenexttest     = 2
sleepbeforetwoftp       = 2
urltimeout              = 10

[SERVER]
reverseshellport        = 12345

[TESTS]     #0:关闭，1:开启
clientSideAttacks       = 1 
testRules               = 1
badTraffic              = 1
fragmentedPackets       = 1
bruteForce              = 1
evasionTechniques       = 1
shellCodes              = 1
denialOfService         = 1
pcapReplay              = 1
normalUsage             = 1
ipReputation            = 1

[TESTS_PARAMS]
ipreputationnbtests     = 10
blacklist 		= blacklist.txt 

`

### 使用

IDS：
将server/python-server.py 上传至IDS
创建用户pytbull

`
useradd -d /var/log/suricata/ -s /bin/bash pytbull
echo "pytbull:pytbull" |chpasswd
usermod -G suricata pytbull
`
执行
`
python pytbull-server.py
`

测试方:

`
git clone ...

`

安装依赖并修改conf/config.cfg

执行
`
 python pytbull -t 192.168.186.130

`


访问 http://192.168.186.129 可以获取可视化报告
