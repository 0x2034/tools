#!/bin/bash 

########################################
####  [+]-- Author: 0x2034 --[+]  ####
####  [+]--    CyberThug    --[+]  ####
########################################

echo -e "\e[1;32m
              ______      __             ________
             / ____/_  __/ /_  ___  ____/_  __/ /_  __  __._____
            / /   / / / / __ \/ _ \/ ___// / / __ \/ / / / __  / 
           / /___/ /_/ / /_/ /  __/ /   / / / / / / /_/ / /_/ /  
           \____/\__, /_.___/\___/_/   /_/ /_/ /_/\__,_/\__, /  
                /____/                                 /____/    
                                                            \e[0m""\e[1;37m0x2034\e[0m"

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
    if nc -zv -w 5 $DOMAIN 53 2>/dev/null || nc -zv -w 5 $DOMAIN 53 2>/dev/null; then
       ip=$(ping -c 1 intelligence.htb | awk -F'[()]' '/PING/{print $2}')
       mkdir -p "$HOME/CyberThug_output/dnsenum"
       Time=$(date +"%Y-%m-%d_%H-%M-%S")
       gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- DNS Enumeration on $DOMAIN --[+]\e[0m' ; echo "" ; dig @$ip $DOMAIN ; echo "" ; echo -e '\e[1;32m---------------\e[0m' ; echo "" ; dig axfr @$ip $DOMAIN ; echo "" ;echo -e '\e[1;32m---------------\e[0m' ; echo "" ; dnsenum --dnsserver $ip -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $HOME/CyberThug_output/dnsenum/dns_enum_${DOMAIN}_${Time} $DOMAIN ; exec bash"
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
  curl $FULL_DOMAIN -k | grep -oE '\b[a-zA-Z0-9._-]+\.(htb|thm|com|org|net|edu|gov|mil|int|co|us|uk|ca|de|jp|fr|au|eg)\b'
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
Usage: 
    ./Script.sh [ip] [domain] flags
    ./Script.sh [ip] flags
    ./Script.sh [domain] flags

flags:
    --no-http: skip port 80 
    --no-https: skip port 443  
    --no-recon: skip recon part 
    --no-network: skip network part
    --no-ping: skip ping part
    --no-portscan: skip port scanning part
"
}

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
           echo -e "\e[1;31m[+]--- For Usage : ./Script.sh -h ---[+]\e[0m"
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
           echo -e "\e[1;31m[+]--- For Usage : ./Script.sh -h ---[+]\e[0m"
           exit 1
       fi
    done
fi
if [ -z "$1" ]; then
    echo -e "\e[1;31m[+]--- For Usage : ./Script.sh -h ---[+]\e[0m"
    exit 1
fi
if [ "$1" == "-h" ]; then
    help
    exit 1
fi
if [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "\e[1;31m[+]--- For Usage : ./Script.sh -h ---[+]\e[0m"
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

trap 'next_step=true' SIGINT
if [ "$next_step" = true ]; then
  next_step=false
fi

main
echo ""
rm $HOME/Downloads/tools/Files/*.state 2>/dev/null ; rm -r $HOME/Downloads/tools/Files/reports 2>/dev/null
echo -e "\e[1;32m------------------[+] Finished [+]---------------------\e[0m"
