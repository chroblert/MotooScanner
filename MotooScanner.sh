#!/bin/bash

#####################################################################################################################################
# 
# Author klion
# Use:  nohup ./MotooScanner.sh 要探测的所有服务端口列表文件 目标的所有真实ip/段[C段]列表文件 保存扫描结果的目录名[随意] 用户名字典文件 密码字典文件 &
#       nohup ./MotooScanner.sh TargetPorts.txt TargetIplist.txt result user.txt pwd.txt &
#       tail -f nohup.out
#
#####################################################################################################################################

if [ $# -eq 0 ];then
    echo -e "\n\e[94m      ===================================================================================================================================\e[0m\n"
    echo -e "\e[91m      Use: \e[0m"
    echo -e "\e[91m          # nohup ./MotooScanner.sh 要探测的所有服务端口列表文件 目标的所有真实ip/段[C段]列表文件 保存扫描结果的目录名[随意] 用户名字典文件 密码字典文件 &\e[0m"
    echo -e "\e[91m          # nohup ./MotooScanner.sh TargetPorts.txt TargetIplist.txt result user.txt pwd.txt &\e[0m\n"
    echo -e "\e[91m          # tail -f nohup.out\e[0m\n"
    echo -e "\e[94m      ===================================================================================================================================\e[0m\n"
    exit
fi

mkdir $3
starttime=`date +'%Y-%m-%d %H:%M:%S'`
times=$(date +%Y)
while read -r port
do
    starts=`date +'%Y-%m-%d %H:%M:%S'`
    echo -e "\n\e[94m===================================================================================\e[0m"
    echo -e "\e[91mTarget Port: $port | Scaning ...... \e[0m\n\n"
    while read -r ip
    do
        echo -e "\n\e[94m===================================================================================\e[0m"
        echo -e "\e[92mTarget IP: $ip  Target Port:$port  |  Scannig ......\e[0m"
        random=$(openssl rand -base64 40|sed 's#[^a-z]##g'|cut -c 6-11)
        masscan -p $port --banners --rate=100 -sS -Pn --http-user-agent "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36" --open-only -oL ${times}_${random}_${port}_scan_res.txt $ip >/dev/null 2>&1
        if [  $? -eq 0 ] ;then  echo -e "\e[92m$ip Scan complete ! \e[0m"; else  echo -e "\e[91mScan Errors ! Please Check Yourself ! \e[0m" ; fi
        echo -e "\e[94m===================================================================================\e[0m\n"
    done < $2
    sleep 1
    grep "open tcp ${port}" *_${port}_*.txt | awk -F " " {'print $4'} > ./${3}/${port}.txt
    # grep "open tcp ${port}" *_${port}_*.txt | awk -F ":" {'print $2'} > ${port}_banner.txt
    rm -fr *_${port}_*.txt
    
    # Get All Web banner
    if [ $port -ge 80 -a  $port -le 90 ] || [ $port -ge 8080 -a $port -le 8090 ] || [ $port -eq 443 ] || [ $port -eq 8443 ];then
	    echo "Get Web banner Begining , wait  ......"
        # 因为 反解 + 加载脚本 后会耗时特别久,所以此处加了-n选项,也留了一个脚本,弟兄们,可根据自己的实际需求来选择脚本[脚本误报很严重]
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=http-headers.nse,http-title.nse,http-robots.txt.nse,http-iis-webdav-vuln.nse -oN ./${3}/Web_${port}_scan_res.txt
        # 可选常规web检测脚本
        # citrix-enum-servers-xml.nse,ssl-heartbleed.nse,http-shellshock.nse,http-cisco-anyconnect.nse
        # http-axis2-dir-traversal.nse,http-backup-finder.nse,http-enum.nse,http-wordpress-users.nse
        # http-methods.nse,http-webdav-scan.nse,http-iis-short-name-brute.nse,http-git.nse
        # 可选漏洞检测脚本 tomcat-cve-2017-12615.nse,http-pulse_ssl_vpn.nse,CVE-2019-19781.nse,struts2-scan.nse,cisco-cve-2019-1937.nse
    fi

    # Java Web Info 
    if [ $port -ge 9200 -a $port -le 9300 ] || [ $port -ge 7001 -a $port -le 7010 ] || [ $port -eq 9999 ];then
	    echo "Java Web Scaning , wait ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/JavaWeb_${port}_scan_res.txt
         # 可选漏洞探测脚本 , weblogic-cve-2018-2894.nse , weblogic-CNVD-C-2019-48814.nse,jdwp-version.nse
    fi

    # SSH Login 此处所用的弱口令字典数量并不多,只针对性的汇总了一批实际成功率相对较高的,考虑到实际速度和命中率的问题,数量尽量控制在了两百以内,medusa 和 hydra 也都是提前测试调教好的
    if [ $port -eq 22 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/SSH_scan_res.txt
        echo "Ssh Login Begining ....."
        medusa -H ./${3}/${port}.txt -u root -e ns -P $5 -t 2 -T 16 -f -M ssh -R 3 -r 5 -O ./${3}/SSH_Login_succeed.txt
        echo "Ssh Login Ending ....."
        # 可选检测脚本 cve-2018-10933
    fi
    
    # RDP
    if [ $port -eq 3389 ];then
        echo "Rdp Scaning ....."
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/RDP_scan_res.txt
        # 可选检测脚本 rdp-vuln-ms12-020.nse
    fi

    # Mssql Login
    if [ $port -eq 1433 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=ms-sql-empty-password.nse -oN ./${3}/Mssql_scan_res.txt
        echo "Mssql Login Begining ....."
        medusa -H ./${3}/${port}.txt -u sa -e ns -P $5 -t 2 -T 16 -f -M mssql -R 3 -r 5 -O ./${3}/Mssql_Login_succeed.txt
        echo "Mssql Login Ending ....."
    fi

    # MySQL Login
    if [ $port -eq 3306 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=mysql-empty-password.nse -oN ./${3}/MySQL_scan_res.txt
        echo "MySQL Login Begining ....."
        medusa -H ./${3}/${port}.txt -u root -e ns -P $5 -t 2 -T 16 -f -M mysql -R 3 -r 5 -O ./${3}/MySQL_Login_succeed.txt
        echo "MySQL Login Ending ....."
    fi

    # Redis Login
    if [ $port -eq 6379 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=redis-info.nse -oN ./${3}/Redis_scan_res.txt
        echo "Redis Login Begining ....."
        hydra -P $5 -e ns -f -o ./${3}/Redis_Login_succeed.txt -M ./${3}/${port}.txt -t 3 -T 16 -w 20 -V redis
        echo "Redis Login Ending ....."
    fi

    # Postgresql Login
    if [ $port -eq 5432 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Postgresql_scan_res.txt
        echo "Postgresql Login Begining ....."
        medusa -H ./${3}/${port}.txt -u postgres -e ns -P $5 -t 2 -T 16 -f -M postgres -R 3 -r 5 -O ./${3}/PgSQL_Login_succeed.txt
        echo "Postgresql Login Ending ....."
    fi

    # SMB Login
    if [ $port -eq 445 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Smb_scan_res.txt
        echo "Smb Login Begining ....."
        hydra -l administrator -P $5 -e ns -f -o ./${3}/Smb_Login_succeed.txt -M ./${3}/${port}.txt -t 3 -T 16 -w 20 -V smb
        echo "Smb Login Ending ....."
        # 可选检测脚本 smb-os-discovery.nse,smb-vuln-ms08-067.nse,smb-vuln-ms17-010.nse
    fi

    # Telnet Login
    if [ $port -eq 23 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Telnet_scan_res.txt
        echo "Telnet Login Begining ....."
        medusa -H ./${3}/${port}.txt -U $4 -e ns -P $5 -t 2 -T 16 -f -M telnet -R 3 -r 5 -O ./${3}/Telnet_Login_succeed.txt
        echo "Telnet Login Ending ....."
    fi

    # ldap Login
    if [ $port -eq 389 ];then
        echo "Ldap Scaning ....."
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Ldap_scan_res.txt
    fi

    # Oracle Sid Brute
    if [ $port -eq 1521 ];then
        echo "Oracle sid enuming ......"
        # 可选检测脚本 oracle-sid-brute.nse
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Oracle_scan_res.txt
    fi

    # MongoDB
    if [ $port -eq 27017 ];then
        echo "MongoDB Gather info ......"
        # 可选检测脚本 mongodb-info.nse 
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/MongoDB_scan_res.txt
    fi

    # FTP
    if [ $port -eq 21 ];then
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=ftp-anon.nse -oN ${3}/Ftp_scan_res.txt
        echo "Ftp Login Begining ....."
        medusa -H ./${3}/${port}.txt -U $4 -e ns -P $5 -t 2 -T 16 -M ftp -R 3 -r 5 -O ./${3}/Ftp_Login_succeed.txt
        echo "Ftp Login Ending ....."
    fi

    # Rsync
    if [ $port -eq 873 ];then
        echo "Rsync Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=rsync-list-modules.nse -oN ./${3}/Rsync_scan_res.txt
    fi

    # NFS
    if [ $port -eq 2049 ]  || [ $port -eq 111 ];then
        echo "NFS Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open --script=nfs-showmount.nse -oN ./${3}/NFS_scan_res.txt
    fi

    # POP3
    if [ $port -eq 110 ] || [ $port -eq 995 ];then
        echo "POP3 Gather info......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Pop3_scan_res.txt
    fi

    # IMAP
    if [ $port -eq 143 ] || [ $port -eq 993 ];then
        echo "Imap Gather Info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Imap_scan_res.txt
    fi

    # SMTP
    if [ $port -eq 25 ]  || [ $port -eq 465 ] || [ $port -eq 587 ];then
        echo "Smtp Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Smtp_scan_res.txt
        # 可选检测脚本 smtp-vuln-cve2019-15846.nse
    fi

    # VNC
    if [ $port -eq 5900 ];then
        echo "Vnc Gather info......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Vnc_scan_res.txt
    fi

    # DNS
    if [ $port -eq 53 ];then
        echo "DNS Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/DNS_scan_res.txt
    fi

    # CouchDB
    if [ $port -eq 5984 ];then
        echo "CouchDB Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/CouchDB_scan_res.txt
    fi

    # FortiOS SSL VPN  Vuln
    if [ $port -eq 10443 ];then
        echo "FortiOS SSL VPN  Vuln Scaning ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/FortiVpn_scan_res.txt
        # 可选检测脚本 http-vuln-cve2018-13379.nse
    fi

    # ike-version
    if [ $port -eq 500 ];then
        echo "ike-version Scaning ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Ike_version_scan_res.txt
        # 可选检测脚本 ike-version.nse
    fi

    # SOCKS
    if [ $port -eq 1080 ];then
        echo "SOCKS Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/SOCKS_scan_res.txt
    fi

    # Nessus
    if [ $port -eq 1241 ];then
        echo "Nessus Gather info ......"
        nmap -p $port -iL ./${3}/${port}.txt -Pn -sT -sV -n -vv --open -oN ./${3}/Nessus_scan_res.txt
    fi

    ends=`date +'%Y-%m-%d %H:%M:%S'`
    start_sec=$(date --date="$starts" +%s);
    end_sec=$(date --date="$ends" +%s);
    final=$((end_sec-start_sec));
    echo -e "\n\e[91m$port端口Banner获取完毕, 共计耗时 $final 秒 \e[0m\n"

done < $1

echo -e "\n\n\n\e[94m===================================================================================\e[0m"
endtime=`date +'%Y-%m-%d %H:%M:%S'`
start_seconds=$(date --date="$starttime" +%s);
end_seconds=$(date --date="$endtime" +%s);
sec=$((end_seconds-start_seconds));
val=$(((end_seconds-start_seconds)/60));
echo -e "\n\e[91m所有端口 & C段全部扫描完毕, 共计耗时 $val 分 | $sec 秒 \e[0m\n"
echo -e "\e[94m===================================================================================\e[0m\n\n\n"

