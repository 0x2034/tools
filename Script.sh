#!/bin/bash 

########################################
####  [+]-- Author: 0xos2034 --[+]  ####
########################################

figlet -ctf slant 0xos2034

network(){
echo ""
echo -e "\e[1;35m--------------- [+] NETWORK [+] --------------\e[0m"
echo ""
if [ "$flag_4" = true ]
then
    :
else 
    if nc -zv -w 5 $DOMAIN 21 2>/dev/null; then
              ftp -n $DOMAIN <<END_SCRIPT
user Anonymous Anonymous
ls        
bye
END_SCRIPT
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 25 2>/dev/null; then
       gnome-terminal -- bash -c "smtp-user-enum -M VRFY -U /usr/share/wordlists/rockyou.txt -t $DOMAIN ; exec bash" 
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 111 2>/dev/null; then
       output=$(timeout 10s showmount -e $DOMAIN 2>&1)
       line_count=$(echo "$output" | wc -l)
       if [ $line_count -gt 1 ]; then
           gnome-terminal -- bash -c "showmount -e $DOMAIN ; exec bash"
       else
           :
       fi
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 139 2>/dev/null || nc -zv -w 5 $DOMAIN 445 2>/dev/null; then
       enum4linux $DOMAIN
       lookupsid.py -no-pass guest@$DOMAIN 20000
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 161 2>/dev/null || nc -zvu -w 5 $DOMAIN 161 2>/dev/null; then
       output=$(timeout 10s snmpwalk -v 2c -c public $DOMAIN 2>/dev/null || timeout 10s snmpwalk -v 1 -c public $DOMAIN 2>/dev/null)
       line_count=$(echo "$output" | wc -l)
       if [ $line_count -gt 5 ]; then
           gnome-terminal -- bash -c "snmpwalk -v 2c -c public $DOMAIN ; snmpwalk -v 1 -c public $DOMAIN ; exec bash"
       else
           :
       fi
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 389 2>/dev/null || nc -zv -w 5 $DOMAIN 636 2>/dev/null; then
       gnome-terminal -- bash -c "python3  $HOME/Downloads/tools/Folders/Windapsearch/windapsearch.py -U --full --dc-ip $DOMAIN ; exec bash"         
    fi
    echo "--------------------------"
    if nc -zv -w 5 $DOMAIN 88 2>/dev/null; then
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
  echo "--------------------------"
  echo "[+]--- Scanning $FULL_DOMAIN ---[+]"
  echo "--------------------------"
  echo ""
  gnome-terminal -- bash -c "nikto -h $FULL_DOMAIN -C all ; exec bash"
  if [[ ! $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
     if [ -z "$HOSTS_ENTRY" ]; then
          ffuf -w /usr/share/wordlists/amass/test.txt -u $FULL_DOMAIN/ -H "Host: FUZZ.${DOMAIN}" >> $HOME/myscript_output/test.txt
          file="$HOME/myscript_output/test.txt"
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
          ffuf -w /usr/share/wordlists/amass/test.txt -u $FULL_DOMAIN/ -H "Host: FUZZ.${DOMAIN}" >> $HOME/myscript_output/test.txt
          file="$HOME/myscript_output/test.txt"
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
  bash  $HOME/Downloads/tools/Files/Gitdumper.sh $FULL_DOMAIN/.git/ $HOME/myscript_output 
  echo "--------------------------"
  python $HOME/Downloads/tools/Folders/DS_Walk/ds_walk.py -u $FULL_DOMAIN
  echo "--------------------------"
  curl $FULL_DOMAIN -k | grep -oE '\b[a-zA-Z0-9._-]+\.(htb|thm|com|org|net|edu|gov|mil|int|co|us|uk|ca|de|jp|fr|au|eg)\b'
  echo "--------------------------"
  python $HOME/Downloads/tools/Files/Hash_extraction.py $FULL_DOMAIN
  echo "--------------------------"
  gnome-terminal -- bash -c "feroxbuster --url $FULL_DOMAIN --random-agent --filter-status 404 -k  ; sleep 5 ; rm $HOME/Downloads/tools/Files/*.state ; exec bash" 
  echo "--------------------------"
  sleep 5
  gnome-terminal -- bash -c "dirsearch -u $FULL_DOMAIN -r --random-agent --exclude-status 404 ; sleep 10 ; rm -rf $HOME/Downloads/tools/Files/reports ; exec bash"
  echo "--------------------------"
  sleep 2
  gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"$FULL_DOMAIN\" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
  echo "--------------------------"
  sleep 5
  gnome-terminal -- bash -c "for STATUS_CODE in \"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\"; do echo 'Running gobuster'; gobuster dir -u \"$FULL_DOMAIN\" -w /usr/share/wordlists/rockyou.txt --no-error --exclude-length 0 \$STATUS_CODE --random-agent; exit_code=\$?; if [[ \$exit_code -eq 0 ]]; then break; fi; done; exec bash"
  if [ "$flag_3" = true ]
  then
      :
  else
      echo -e "\e[1;36m[+] RECON [+]\e[0m"
  fi
}
web_1(){
   echo ""
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
}
main(){
    if ping -c3 $DOMAIN 2>/dev/null; then
        nmap -A -Pn $DOMAIN
        gnome-terminal -- bash -c "nmap $DOMAIN -Pn -p- ; exec bash" 
        web_1
        network 
    else
        echo -e "\e[1;36m[+]--- Second Attempt ---[+]\e[0m"
        echo ""
        if ping -c25 $DOMAIN 2>/dev/null; then
            nmap -A -Pn $DOMAIN
            gnome-terminal -- bash -c "nmap $DOMAIN -Pn -p- ; exec bash"
            web_1
            network 
        else
            echo -e "\e[1;31m[+]--- The Target Is Not Reachable ---[+]\e[0m"
            exit 1
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
"
}

declare -A seen_flags
declare -a valid_flags=("--no-http" "--no-https" "--no-recon" "--no-network")
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
        echo "$1 $2" | sudo tee -a /etc/hosts 
        echo "Added to => /etc/hosts"
        echo "--------------------------"
    fi
else
    DOMAIN=$1
    HOSTS_ENTRY=""
fi 
main
echo ""
echo -e "\e[1;32m------------------[+] Finished [+]---------------------\e[0m"
