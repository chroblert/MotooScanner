
## 0x01 用法
```
# nohup ./scan.sh 要探测的所有服务端口列表文件 目标的所有真实ip/段[C段]列表文件 保存扫描结果的目录名[随意] 用户名字典文件 密码字典文件 &
# nohup ./scan.sh TargetPorts.txt TargetIplist.txt result user.txt pwd.txt &
# tail -f nohup.out
```

## 0x02 大致工作流程
```
脚本自身没有任何技术含量,纯粹是 组装 Masscan + Nmap [ 自行选择性是否加脚本 ] + Medusa + Hydra 相互配合自动探测 
[ 由于是 同时针对多个ip段扫一个端口,而非针对一个ip同时扫一堆端口,加之用的只是常规循环(单线程),理论上对常规防护规避效果应该稍好 ]
先利用masscan 集中对目标的所有C段进行快速端口探测,而后再利用nmap对开放相应端口的ip进行二次的精度端口服务识别
之后再针对一些可快速getshell的基础服务,进行初期弱口令尝试
尤其适用于一些目标规模较大[ 比如,横跨好几百个真实C段 ], 然后想从暴露在外部的各类基础服务端口快速寻找突破口的场景
```


## 0x03 依赖安装 
### [ 以ubuntu 16.04 64位为例，为确保可靠性，建议弟兄们自行手动安装，毕竟，磨刀不误砍柴工 ]

### 编译安装最新版masscan
```
# apt-get install git gcc make libpcap-dev clang -y
# cd masscan-1.0.5/
# make
# man masscan
```

### 编译安装最新版 nmap
```
# apt-get install openssl libssl-dev libssh2-1-dev build-essential -y
# wget https://nmap.org/dist/nmap-7.80.tar.bz2
# tar xf nmap-7.80.tar.bz2 && cd nmap-7.80 && chmod +x ./* && ./configure && make && make install
```

### 编译安装最新版 medusa
```
# apt-get install build-essential libssl-dev libpq5 libpq-dev libssh2-1 libssh2-1-dev libgcrypt11-dev libgnutls-dev libsvn-dev freerdp libfreerdp-dev -y
# wget http://www.foofus.net/jmk/tools/medusa-2.2.tar.gz
# tar xf medusa-2.2.tar.gz && cd medusa-2.2/ && ./configure && make && make install
```

### 编译安装最新版 hydra
```
# apt-get update
# apt-get install git libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird-dev libgcrypt11-dev libncurses5-dev -y
# 7z x thc-hydra-9.0.7z && cd thc-hydra-9.0/ && chmod +x ./* && ./configure && make && make install
```

### 脚本说明
```
脚本初衷只为尽量简化我们日常渗透中的一些例行的重复性动作,利用bash就地取材,快速实现的一个极为廉价的外部搜集工具
所有 "扫描" 和 "弱口令探测" 的结果均已按照其所对应的 "端口" 和 "服务名" 分类保存在当前目录中的result目录下,目录名可自定义
分类存主要也是为了方便弟兄们后续好再针对目标开放某个端口的ip列表进行集中操作
为在保证精度的情况下尽量加快速度,经过多次实测,中间省去了很多判断和校验
有些输出信息之所以没直接丢到null里,主要是为了让弟兄们能更清晰的看到整个过程
nmap 默认的帐号密码字典,脚本已事先优化增强过
服务端口也已按能快速getshell的难以程度优先级排好序了,另外,根据个人平时经验基本已覆盖了一些最常见的可能会存在利用机会的服务端口
实际速度根据目标的不同,速度耗时都是不同的 [实测九百个C段,目前初步预估得三天+ 左右],用时间换精度,尽力避免重复劳动
另外,vps要靠谱,不然长时间高频大流量很容易被封,这个就需要弟兄们自己解决了
```


### 脚本仅限于安全研究学习和授权渗透之用
### 严禁将其用于任何恶意非法用途,由此所产生的一些法律责任,均由使用者自行承担
