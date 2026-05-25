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



async def main():
    sysmon_dest_path = path.join(environ["USERPROFILE"], "Desktop", "sysmon")
    sysmon_file_name = "Microsoft-Windows-Sysmon%4Operational.evtx"
    sysmon_src_path = path.abspath("C:\\Windows\\System32\\winevt\\Logs")
    keyword = ["whoami", "tasklist", "quser"]
    extension = [".bat", ".cmd", ".rar"]
    username = input("input username: ")
    password = input("input password: ")
    passwordhashed = hashlib.sha1(password.encode("utf-8"))
    try:
        cred = {"username": username, "password": passwordhashed.hexdigest()}
        res = requests.post(url="http://127.0.0.1:8000/auth", json=cred)
        if res.status_code != 200:
            raise Exception("credential invalid")
        message = res.json()
        token = message["message"]
        print(f"token received: {token}")
        async with websockets.connect(
            f"ws://127.0.0.1:8000/ws?token={token}"
        ) as socket:
            with Evtx.Evtx(
                filename=path.join(sysmon_src_path, sysmon_file_name)
            ) as log:
                while True:
                    # header = log.get_file_header()
                    for record in log.records():
                        event = record.lxml()
                        soup = BeautifulSoup(etree.tostring(event), features="xml")
                        payload = {"event": soup.__str__()}
                        await socket.send(message=json.dumps(payload), text=True)
                        break
                    break
            await socket.close()

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
