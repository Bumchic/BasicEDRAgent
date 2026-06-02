import websockets
import requests
from Evtx import Evtx
from os import path, environ
from lxml import etree
from requests import Session, post
from time import sleep
from bs4 import BeautifulSoup
import asyncio
import json
import hashlib


def get_token(username: str, password: str) -> websockets.ClientConnection:
    cred = {"username": username, "password": password}
    res = requests.post(url="http://127.0.0.1:8000/auth", json=cred)
    if res.status_code != 200:
        raise Exception("credential invalid")
    message = res.json()
    token = message["message"]
    print(f"token received: {token}")
    return token


async def main():
    sysmon_file_name = "Microsoft-Windows-Sysmon%4Operational.evtx"
    sysmon_src_path = path.abspath("C:\\Windows\\System32\\winevt\\Logs")
    username = input("input username: ")
    password = input("input password: ")
    passwordhashed = hashlib.sha1(password.encode("utf-8"))
    passwordhashedhex = passwordhashed.hexdigest()
    #token = get_token(username=username, password=passwordhashedhex)
    try:
        async for socket in websockets.connect(f"ws://127.0.0.1:8000/ws?token={get_token(username=username, password=passwordhashedhex)}"):
            try:
                with Evtx.Evtx(
                        filename=path.join(sysmon_src_path, sysmon_file_name)
                    ) as log:
                    while True:
                            # header = log.get_file_header()
                            print('reading logs...')
                            for record in log.records():
                                event = record.lxml()
                                soup = BeautifulSoup(etree.tostring(event), features="xml")
                                payload = {"event": soup.__str__()}
                                await socket.send(message=json.dumps(payload), text=True)
                                await socket.recv()
                            break
            except websockets.exceptions.ConnectionClosed as e:
                print('diconnected exception: ' + e.__str__())
                print('attempting reconnection')
                sleep(5)
                continue
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
