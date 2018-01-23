#!/bin/bash
#A script to enumerate local information from a Linux host
v="version 0.7"
#@rebootuser

#help function
usage () 
{ 
  echo -e "\n\e[00;31m#########################################################\e[00m" 
  echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
  echo -e "\e[00;31m#########################################################\e[00m"
  echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
  echo -e "\e[00;33m# $v\e[00m\n"
  echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

	echo "OPTIONS:"
	echo "-k	Enter keyword"
	echo "-e	Enter export location"
	echo "-t	Include thorough (lengthy) tests"
	echo "-r	Enter report name" 
	echo "-h	Displays this help text"
	echo -e "\n"
	echo "Running with no options = limited scans/no output file"
	
  echo -e "\e[00;31m#########################################################\e[00m"		
}

header()
{
  echo -e "\n\e[00;31m#########################################################\e[00m" 
  echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m" 
  echo -e "\e[00;31m#########################################################\e[00m" 
  echo -e "\e[00;33m# www.rebootuser.com\e[00m" 
  echo -e "\e[00;33m# $version\e[00m\n" 
}

debug_info()
{
  echo "Debug Info" 

  if [ "$keyword" ]; then 
  	echo "keyword = $keyword" 
  fi

  if [ "$report" ]; then 
  	echo "report name = $report" 
  fi

  if [ "$export" ]; then 
  	echo "export location = $export" 
  fi

  if [ "$thorough" ]; then 
  	echo "thorough tests = enabled" 
  else 
  	echo "thorough tests = disabled" 
  fi

  sleep 2

  if [ "$export" ]; then
    mkdir $export 2>/dev/null
    format=$export/LinEnum-export-`date +"%d-%m-%y"`
    mkdir $format 2>/dev/null
  fi

  who=`whoami` 2>/dev/null 
  echo -e "\n" 

  echo -e "\e[00;33mScan started at:"; date 
  echo -e "\e[00m\n" 
}

system_info()
{
  echo -e "\e[00;33m### SYSTEM ##############################################\e[00m" 

  #basic kernel info
  unameinfo=`uname -a 2>/dev/null`
  if [ "$unameinfo" ]; then
    echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo\n"
  fi

  procver=`cat /proc/version 2>/dev/null`
  if [ "$procver" ]; then
    echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver\n"
  fi

  #search all *-release files for version info
  release=`cat /etc/*-release 2>/dev/null`
  if [ "$release" ]; then
    echo -e "\e[00;31mSpecific release information:\e[00m\n$release\n" 
  fi

  #target hostname info
  hostnamed=`hostname 2>/dev/null`
  if [ "$hostnamed" ]; then
    echo -e "\e[00;31mHostname:\e[00m\n$hostnamed\n" 
  fi
}

user_info()
{
  echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" 

  #current user details
  currusr=`id 2>/dev/null`
  if [ "$currusr" ]; then
    echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr\n" 
  fi

  #last logged on user information
  lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
  if [ "$lastlogedonusrs" ]; then
    echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs\n" 
  fi


  #who else is logged on
  loggedonusrs=`w 2>/dev/null`
  if [ "$loggedonusrs" ]; then
    echo -e "\e[00;31mWho else is logged on:\e[00m\n$loggedonusrs\n"
  fi

  #lists all id's and respective group(s)
  grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
  if [ "$grpinfo" ]; then
    echo -e "\e[00;31mGroup memberships:\e[00m\n$grpinfo"
    #added by phackt - look for adm group (thanks patrick)
    adm_users=$(echo -e "$grpinfo" | grep "(adm)")
    if [[ ! -z $adm_users ]];
    then
      echo -e "\nSeems we met some admin users!!!\n"
      echo -e "$adm_users\n"
    fi
    echo -e "\n"
  else 
    :
  fi

  #checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
  hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
  if [ "$hashesinpasswd" ]; then
    echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd\n"
  fi
   
  #locate custom user accounts with some 'known default' uids
  # optimize the code
  readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
  if [ "$readpasswd" ]; then
    echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd\n"
    if [ "$export" ] then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/passwd $format/etc-export/passwd 2>/dev/null
    fi
  fi


  #checks to see if the shadow file can be read
  readshadow=`cat /etc/shadow 2>/dev/null`
  if [ "$readshadow" ]; then
    echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow" 
    echo -e "\n" 
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/shadow $format/etc-export/shadow 2>/dev/null
    fi
  fi


  #checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
  readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
  if [ "$readmasterpasswd" ]; then
    echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd\n"
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
    fi
  fi


  #all root accounts (uid 0)
  # TODO optimize
  echo -e "\e[00;31mSuper user account(s):\e[00m" | tee -a $report 2>/dev/null; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null 
  echo -e "\n" 

  #pull out vital sudoers info
  # TODO Optimize
  sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
  if [ "$sudoers" ]; then
    echo -e "\e[00;31mSudoers configuration (condensed):\e[00m$sudoers" | tee -a $report 2>/dev/null
    echo -e "\n" 
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
    fi
  fi

  #can we sudo without supplying a password
  sudoperms=`echo '' | sudo -S -l 2>/dev/null`
  if [ "$sudoperms" ]; then
    echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms\n"
  fi

  #known 'good' breakout binaries
  sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
  if [ "$sudopwnage" ]; then
    echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage\n"
  fi

  #checks to see if roots home directory is accessible
  rthmdir=`ls -ahl /root/ 2>/dev/null`
  if [ "$rthmdir" ]; then
    echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir\n"
  fi

  #displays /home directory permissions - check if any are lax
  homedirperms=`ls -ahl /home/ 2>/dev/null`
  if [ "$homedirperms" ]; then
    echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms\n"
  fi

  #looks for files we can write to that don't belong to us
  if [ "$thorough" = "1" ]; then
    grfilesall=`find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -al {} \; 2>/dev/null`
    if [ "$grfilesall" ]; then
      echo -e "\e[00;31mFiles not owned by user but writable by group:\e[00m\n$grfilesall\n"
    fi
  fi

  #looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
  if [ "$thorough" = "1" ]; then
    wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
  	if [ "$wrfileshm" ]; then
  		echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm\n"
      if [ "$export" ]; then
        mkdir $format/wr-files/ 2>/dev/null
        for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
      fi
  	fi
  fi

  #lists current user's home directory contents
  if [ "$thorough" = "1" ]; then
  homedircontents=`ls -ahl ~ 2>/dev/null`
  	if [ "$homedircontents" ] ; then
  		echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents\n"
  	fi
  fi

  #checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
  if [ "$thorough" = "1" ]; then
  sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
  	if [ "$sshfiles" ]; then
  		echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles\n" 
      if [ "$export" ]; then
        mkdir $format/ssh-files/ 2>/dev/null
        for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
      fi
  	fi
  fi


  #is root permitted to login via ssh
  sshrootlogin=`grep "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | awk '{print  $2}'`
  if [ "$sshrootlogin" = "yes" ]; then
    echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m" ; grep "^PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null
    echo -e "\n" 
  fi
}

environmental_info()
{
  echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" 

  #env information
  envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
  if [ "$envinfo" ]; then
    echo -e "\e[00;31m Environment information:\e[00m\n$envinfo\n" 
  else 
    :
  fi

  #check if selinux is enabled
  sestatus=`sestatus 2>/dev/null`
  if [ "$sestatus" ]; then
    echo -e "\e[00;31mSELinux seems present:\e[00m\n$sestatus\n"
  fi

  #phackt

  #current path configuration
  pathinfo=`echo $PATH 2>/dev/null`
  if [ "$pathinfo" ]; then
    echo -e "\e[00;31mPath information:\e[00m\n$pathinfo\n"
  fi

  #lists available shells
  shellinfo=`cat /etc/shells 2>/dev/null`
  if [ "$shellinfo" ]; then
    echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo\n"
  fi

  #current umask value with both octal and symbolic output
  umask=`umask -S 2>/dev/null & umask 2>/dev/null`
  if [ "$umask" ]; then
    echo -e "\e[00;31mCurrent umask value:\e[00m\n$umask\n"
  fi

  #umask value as in /etc/login.defs
  umaskdef=`grep -i "^UMASK" /etc/login.defs 2>/dev/null`
  if [ "$umaskdef" ]; then
    echo -e "\e[00;31mumask value as specified in /etc/login.defs:\e[00m\n$umaskdef\n" 
  fi

  #password policy information as stored in /etc/login.defs
  logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
  if [ "$logindefs" ]; then
    echo -e "\e[00;31mPassword and storage information:\e[00m\n$logindefs\n" 
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
    fi
  fi
}

job_info()
{
  echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m" 

  #are there any cron jobs configured
  cronjobs=`ls -la /etc/cron* 2>/dev/null`
  if [ "$cronjobs" ]; then
    echo -e "\e[00;31mCron jobs:\e[00m\n$cronjobs\n" 
  fi

  #can we manipulate these jobs in any way
  cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
  if [ "$cronjobwwperms" ]; then
    echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms\n"
  fi

  #contab contents
  crontab=`cat /etc/crontab 2>/dev/null`
  if [ "$crontab" ]; then
    echo -e "\e[00;31mCrontab contents:\e[00m\n$crontab\n"
  fi

  crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
  if [ "$crontabvar" ]; then
    echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar\n"
  fi

  anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
  if [ "$anacronjobs" ]; then
    echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m\n$anacronjobs\n" 
  fi

  anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
  if [ "$anacrontab" ]; then
    echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab\n" 
  fi

  #pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
  cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
  if [ "$cronother" ]; then
    echo -e "\e[00;31mJobs held by all users:\e[00m\n$cronother\n" 
  fi
}

networking_info()
{
  echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m" 

  #nic information
  nicinfo=`/sbin/ifconfig -a 2>/dev/null`
  if [ "$nicinfo" ]; then
    echo -e "\e[00;31mNetwork & IP info:\e[00m\n$nicinfo\n" 
  fi

  arpinfo=`arp -a 2>/dev/null`
  if [ "$arpinfo" ]; then
    echo -e "\e[00;31mARP history:\e[00m\n$arpinfo\n" 
  fi

  #dns settings
  nsinfo=`grep "nameserver" /etc/resolv.conf 2>/dev/null`
  if [ "$nsinfo" ]; then
    echo -e "\e[00;31mNameserver(s):\e[00m\n$nsinfo\n" 
  fi

  #default route configuration
  defroute=`route 2>/dev/null | grep default`
  if [ "$defroute" ]; then
    echo -e "\e[00;31mDefault route:\e[00m\n$defroute\n" 
  fi

  #listening TCP
  tcpservs=`netstat -antp 2>/dev/null`
  if [ "$tcpservs" ]; then
    echo -e "\e[00;31mListening TCP:\e[00m\n$tcpservs\n"
  fi

  #listening UDP
  udpservs=`netstat -anup 2>/dev/null`
  if [ "$udpservs" ]; then
    echo -e "\e[00;31mListening UDP:\e[00m\n$udpservs\n"
  fi
}

services_info()
{
  echo -e "\e[00;33m### SERVICES #############################################\e[00m" 

  #running processes
  psaux=`ps aux 2>/dev/null`
  if [ "$psaux" ]; then
    echo -e "\e[00;31mRunning processes:\e[00m\n$psaux\n" 
  fi

  #lookup process binary path and permissisons
  procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
  if [ "$procperm" ]; then
    echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm\n" 
    if [ "$export" ]; then
      procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
      mkdir $format/ps-export/ 2>/dev/null
      for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
    fi
  fi

  
  #anything 'useful' in inetd.conf
  inetdread=`cat /etc/inetd.conf 2>/dev/null`
  if [ "$inetdread" ]; then
    echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m\n$inetdread\n" 
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
    fi
  fi


  #very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
  inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
  if [ "$inetdbinperms" ]; then
    echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms\n" 
  fi

  xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
  if [ "$xinetdread" ]; then
    echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m\n$xinetdread\n" 
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
    fi
  fi


  xinetdincd=`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
  if [ "$xinetdincd" ]; then
    echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null 
    echo -e "\n" 
  fi

  #very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
  xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
  if [ "$xinetdbinperms" ]; then
    echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms\n" 
  fi

  initdread=`ls -la /etc/init.d 2>/dev/null`
  if [ "$initdread" ]; then
    echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m\n$initdread\n" 
  fi  

  #init.d files NOT belonging to root!
  initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
  if [ "$initdperms" ]; then
    echo -e "\e[00;31m/etc/init.d/ files not belonging to root (uid 0):\e[00m\n$initdperms\n"
  fi

  rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
  if [ "$rcdread" ]; then
    echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m\n$rcdread\n"
  fi

  #init.d files NOT belonging to root!
  rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
  if [ "$rcdperms" ]; then
    echo -e "\e[00;31m/etc/rc.d/init.d files not belonging to root (uid 0):\e[00m\n$rcdperms\n"
  fi

  usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
  if [ "$usrrcdread" ]; then
    echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread\n" 
  fi

  #rc.d files NOT belonging to root!
  usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
  if [ "$usrrcdperms" ]; then
    echo -e "\e[00;31m/usr/local/etc/rc.d files not belonging to root (uid 0):\e[00m\n$usrrcdperms\n" 
  fi
}

software_configs()
{
  echo -e "\e[00;33m### SOFTWARE #############################################\e[00m" 

  #sudo version - check to see if there are any known vulnerabilities with this
  sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
  if [ "$sudover" ]; then
    echo -e "\e[00;31mSudo version:\e[00m\n$sudover\n" 
  fi

  #mysql details - if installed
  mysqlver=`mysql --version 2>/dev/null`
  if [ "$mysqlver" ]; then
    echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver\n"
  fi

  #checks to see if root/root will get us a connection
  mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
  if [ "$mysqlconnect" ]; then
    echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect\n"
  fi

  #mysql version details
  mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
  if [ "$mysqlconnectnopass" ]; then
    echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass\n" 
  fi

  #postgres details - if installed
  postgver=`psql -V 2>/dev/null`
  if [ "$postgver" ]; then
    echo -e "\e[00;31mPostgres version:\e[00m\n$postgver\n"
  fi

  #checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
  postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
  if [ "$postcon1" ]; then
    echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1\n"
  fi

  postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
  if [ "$postcon11" ]; then
    echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11\n"
  fi

  postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
  if [ "$postcon2" ]; then
    echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2\n"
  fi

  postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
  if [ "$postcon22" ]; then
    echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22\n"
  fi

  #apache details - if installed
  apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
  if [ "$apachever" ]; then
    echo -e "\e[00;31mApache version:\e[00m\n$apachever\n"
  fi

  #what account is apache running under
  #apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
  apacheusr=`grep -o "APACHE_RUN.*" /etc/apache2/envvars 2>/dev/null`
  if [ "$apacheusr" ]; then
    echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr\n"
    if [ "$export" ]; then
      mkdir --parents $format/etc-export/apache2/ 2>/dev/null
      cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
    fi
  fi


  #installed apache modules
  apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
  if [ "$apachemodules" ]; then
    echo -e "\e[00;31mInstalled Apache modules:\e[00m\n$apachemodules\n"
  fi

  #anything in the default http home dirs
  apachehomedirs=`ls -alhR /var/www/ /srv/www/htdocs/ /usr/local/www/apache2/data/ /opt/lampp/htdocs/ 2>/dev/null`
  if [ "$apachehomedirs" ]; then
    echo -e "\e[00;31mAnything in the Apache home dirs?:\e[00m\n$apachehomedirs\n"
  fi
}

interesting_files()
{
  echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m" 

  #checks to see if various files are installed
  echo -e "\e[00;31mUseful file locations:\e[00m" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null 
  echo -e "\n" 

  #limited search for installed compilers
  compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
  if [ "$compiler" ]; then
    echo -e "\e[00;31mInstalled compilers:\e[00m\n$compiler\n"
  fi

  #manual check - lists out sensitive files, can we read/modify etc.
  echo -e "\e[00;31mCan we read/write sensitive files:\e[00m" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null 
  echo -e "\n" 

  #search for suid files - this can take some time so is only 'activated' with thorough scanning switch (as are all suid scans below)
  if [ "$thorough" = "1" ]; then
  findsuid=`find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$findsuid" ]; then
  		echo -e "\e[00;31mSUID files:\e[00m\n$findsuid\n"
      if [ "$export" ]; then
        mkdir $format/suid-files/ 2>/dev/null
        for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
      fi
  	fi
  fi


  #list of 'interesting' suid files - feel free to make additions
  if [ "$thorough" = "1" ]; then
  intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'emacs'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null`
  	if [ "$intsuid" ]; then
  		echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid\n"
  	fi
  fi

  #lists word-writable suid files
  if [ "$thorough" = "1" ]; then
  wwsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$wwsuid" ]; then
  		echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid\n"
  	fi
  fi

  #lists world-writable suid files owned by root
  if [ "$thorough" = "1" ]; then
  wwsuidrt=`find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$wwsuidrt" ]; then
  		echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt\n"
  	fi
  fi

  #search for guid files - this can take some time so is only 'activated' with thorough scanning switch (as are all guid scans below)
  if [ "$thorough" = "1" ]; then
  findguid=`find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$findguid" ]; then
  		echo -e "\e[00;31mGUID files:\e[00m\n$findguid\n" 
      if [ "$export" ]; then
        mkdir $format/guid-files/ 2>/dev/null
        for i in $findguid; do cp $i $format/guid-files/; done 2>/dev/null
      fi
  	fi
  fi

  #list of 'interesting' guid files - feel free to make additions
  if [ "$thorough" = "1" ]; then
  intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null`
  	if [ "$intguid" ]; then
  		echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid\n" 
  	fi
  fi

  #lists world-writable guid files
  if [ "$thorough" = "1" ]; then
  wwguid=`find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$wwguid" ]; then
  		echo -e "\e[00;31mWorld-writable GUID files:\e[00m\n$wwguid\n"
  	fi
  fi

  #lists world-writable guid files owned by root
  if [ "$thorough" = "1" ]; then
  wwguidrt=`find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$wwguidrt" ]; then
  		echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt\n"
  	fi
  fi

  #list all world-writable files excluding /proc
  if [ "$thorough" = "1" ]; then
  wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
  	if [ "$wwfiles" ]; then
  		echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m\n$wwfiles\n"
      if [ "$export" ]; then
        mkdir $format/ww-files/ 2>/dev/null
        for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
      fi
  	fi
  fi


  #are any .plan files accessible in /home (could contain useful information)
  usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
  if [ "$usrplan" ]; then
    echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan\n" 
    if [ "$export" ]; then
      mkdir $format/plan_files/ 2>/dev/null
      for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
    fi
  fi


  bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
  if [ "$bsdusrplan" ]; then
    echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan\n"
    if [ "$export" ]; then
      mkdir $format/plan_files/ 2>/dev/null
      for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
    fi
  fi


  #are there any .rhosts files accessible - these may allow us to login as another user etc.
  rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
  if [ "$rhostsusr" ]; then
    echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr\n" 
    if [ "$export" ]; then
      mkdir $format/rhosts/ 2>/dev/null
      for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi
  fi


  bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
  if [ "$bsdrhostsusr" ]; then
    echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr\n"
    if [ "$export" ]; then
      mkdir $format/rhosts 2>/dev/null
      for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi
  fi


  rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
  if [ "$rhostssys" ]; then
    echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys\n"
    if [ "$export" ]; then
      mkdir $format/rhosts/ 2>/dev/null
      for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
    fi
  fi


  #list nfs shares/permisisons etc.
  nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
  if [ "$nfsexports" ]; then
    echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports\n"
    if [ "$export" ]; then
      mkdir $format/etc-export/ 2>/dev/null
      cp /etc/exports $format/etc-export/exports 2>/dev/null
    fi
  fi


  if [ "$thorough" = "1" ]; then
    #phackt
    #displaying /etc/fstab
    fstab=`cat /etc/fstab 2>/dev/null`
    if [ "$fstab" ]; then
      echo -e "\e[00;31mNFS displaying partitions and filesystems - you need to check if exotic filesystems\e[00m$fstab\n"
    fi
  fi

  #looking for credentials in /etc/fstab
  #fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
  fstab=`grep -Po "(?:username=(.*?)),|(?:password=(.*?)),|(?:domain=(.*?)),|"`
  if [ "$fstab" ]; then
    echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab\n"
    if [ "$export" ]; then
      mkdir $format/etc-exports/ 2>/dev/null
      cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
    fi
  fi


  fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
  if [ "$fstabcred" ]; then
      echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred\n" 
    if [ "$export" ]; then
      mkdir $format/etc-exports/ 2>/dev/null
      cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
    fi
  fi


  #use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
  if [ "$keyword" = "" ]; then
    echo -e "Can't search *.conf files as no keyword was entered\n" 
    else
      confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
      if [ "$confkey" ]; then
        echo -e "\e[00;Found keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey\n" 
        if [ "$export" ]; then
          confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
          mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
          for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
        fi
       else 
      	echo -e "\e[00;31mFind keyword ($keyword) in .conf files (recursive 4 levels):\e[00m" 
      	echo -e "'$keyword' not found in any .conf files\n" 
      fi
  fi

  #use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
  if [ "$keyword" = "" ];then
    echo -e "Can't search *.log files as no keyword was entered\n" 
    else
      logkey=`find / -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
      if [ "$logkey" ]; then
        echo -e "\e[00;31mFind keyword ($keyword) in .log files (output format filepath:identified line number where keyword appears):\e[00m\n$logkey" 
        echo -e "\n" 
        if [ "$export" ]; then
          logkeyfile=`find / -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
          mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
          for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
        fi
      else 
      	echo -e "\e[00;31mFind keyword ($keyword) in .log files (recursive 2 levels):\e[00m" 
      	echo -e "'$keyword' not found in any .log files"
      	echo -e "\n" 
      fi
  fi

  #use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
  if [ "$keyword" = "" ];then
    echo -e "Can't search *.ini files as no keyword was entered\n" 
    else
      inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
      if [ "$inikey" ]; then
        echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey\n"
        # Export
        if [ "$export" ]; then
          inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
          mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
          for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
        fi
      else 
      	echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 2 levels):\e[00m" 
      	echo -e "'$keyword' not found in any .ini files\n"
      fi
  fi

  #quick extract of .conf files from /etc - only 1 level
  allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
  if [ "$allconf" ]; then
    echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m\n$allconf\n"
    if [ "$export" ]; then
      mkdir $format/conf-files/ 2>/dev/null
      for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
    fi
  fi


  #extract any user history files that are accessible
  usrhist=`ls -la ~/.*_history 2>/dev/null`
  if [ "$usrhist" ]; then
    echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist\n"
    if [ "$export" ]; then
      mkdir $format/history_files/ 2>/dev/null
      for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
    fi
  fi


  #can we read roots *_history files - could be passwords stored etc.
  roothist=`ls -la /root/.*_history 2>/dev/null`
  if [ "$roothist" ]; then
    echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist\n"
    if [ "$export" ]; then
      mkdir $format/history_files/ 2>/dev/null
      cp $roothist $format/history_files/ 2>/dev/null
    fi
  fi


  #is there any mail accessible
  readmail=`ls -la /var/mail 2>/dev/null`
  if [ "$readmail" ]; then
    echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail\n"
  fi

  #can we read roots mail
  readmailroot=`head /var/mail/root 2>/dev/null`
  if [ "$readmailroot" ]; then
    echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot\n"
    if [ "$export" ]; then
      mkdir $format/mail-from-root/ 2>/dev/null
      cp $readmailroot $format/mail-from-root/ 2>/dev/null
    fi
  fi

}
docker_checks()
{
  #specific checks - check to see if we're in a docker container
  dockercontainer=` grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
  if [ "$dockercontainer" ]; then
    echo -e "\e[00;33mLooks like we're in a Docker container:\e[00m\n$dockercontainer\n"
  fi

  #specific checks - check to see if we're a docker host
  dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
  if [ "$dockerhost" ]; then
    echo -e "\e[00;33mLooks like we're hosting Docker:\e[00m\n$dockerhost\n"
  fi

  #specific checks - are we a member of the docker group
  dockergrp=`id | grep -i docker 2>/dev/null`
  if [ "$dockergrp" ]; then
    echo -e "\e[00;33mWe're a member of the (docker) group - could possibly misuse these rights!:\e[00m\n$dockergrp\n"
  fi

  #specific checks - are there any docker files present
  dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
  if [ "$dockerfiles" ]; then
    echo -e "\e[00;31mAnything juicy in the Dockerfile?:\e[00m\n$dockerfiles\n"
  fi

  #specific checks - are there any docker files present
  dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
  if [ "$dockeryml" ]; then
    echo -e "\e[00;31mAnything juicy in docker-compose.yml?:\e[00m\n$dockeryml\n"
  fi
}

lxc_container_checks()
{
  #specific checks - are we in an lxd/lxc container
  lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
  if [ "$lxccontainer" ]; then
    echo -e "\e[00;33mLooks like we're in an lxc container:\e[00m\n$lxccontainer\n"
  fi

  #specific checks - are we a member of the lxd group
  lxdgroup=`id | grep -i lxd 2>/dev/null`
  if [ "$lxdgroup" ]; then
    echo -e "\e[00;33mWe're a member of the (lxd) group - could possibly misuse these rights!:\e[00m\n$lxdgroup\n"
  fi

}

footer()
{
  echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m" 
}

call_each()
{
  header
  debug_info
  system_info
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "h:k:r:e:t" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    t) thorough=1;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done



call_each | tee -a $report 2> /dev/null
#EndOfScript
