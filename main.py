from concurrent.futures import thread
from sys import flags
import threading

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
import datetime
from robocopy import robocopy
from win32evtlog import EvtSubscribe
import win32evtlog
import time
import queue

serverhost = "10.0.2.15"
# serverhost = "127.0.0.1"
serverport = 8000
serveraddr = f"{serverhost}:{serverport}"


def get_token(username: str, password: str) -> str:
    cred = {"username": username, "password": password}
    res = requests.post(url=f"http://{serveraddr}/auth", json=cred)
    if res.status_code != 200:
        raise Exception("credential invalid")
    message = res.json()
    token = message["message"]
    print(f"token received: {token}")
    return token


async def main():
    sysmon_dest_name = f"{environ['USERPROFILE']}/Desktop/Sysmon"
    sysmon_file_name = "Microsoft-Windows-Sysmon%4Operational.evtx"
    sysmon_src_path = path.abspath("C:\\Windows\\System32\\winevt\\Logs")
    username = input("input username: ")
    password = input("input password: ")
    passwordhashed = hashlib.sha1(password.encode("utf-8"))
    passwordhashedhex = passwordhashed.hexdigest()
    # loop = asyncio.get_running_loop()
    #
    q = queue.Queue()
    try:
        while True:
            try:
                print("authorizing")
                token = get_token(username=username, password=passwordhashedhex)
                url = f"ws://{serveraddr}/ws?token={token}"
                print(f"connecting to {url}")
                async with websockets.connect(url) as socket:
                    today = datetime.datetime.now().date()
                    loop = asyncio.get_running_loop()
                    # async def cuteventfromtoday():
                    #     with Evtx.Evtx(
                    #         filename=path.join(sysmon_dest_name, sysmon_file_name),
                    #     ) as log:
                    #         for record in log.records():
                    #             event = record.lxml()
                    #             soup = BeautifulSoup(
                    #                 etree.tostring(event), features="xml"
                    #             )
                    #             timecreated = str(
                    #                 soup.find("TimeCreated").get("SystemTime")  # type:ignore
                    #             )  # type: ignore
                    #             timecreated_date = timecreated.split(" ")[0]
                    #             timecreated_date_split = timecreated_date.split("-")
                    #             year = int(timecreated_date_split[0])
                    #             month = int(timecreated_date_split[1])
                    #             day = int(timecreated_date_split[2])
                    #             datetime_timecreated = datetime.datetime(
                    #                 year=year, month=month, day=day
                    #             )
                    #             if datetime_timecreated.date() < today:
                    #                 print(timecreated)
                    #                 continue
                    #             print(datetime_timecreated.date())
                    #             print(today)
                    #         pass

                    # async def readandsendlog():
                    #     with Evtx.Evtx(
                    #         filename=path.join(sysmon_dest_name, sysmon_file_name),
                    #     ) as log:
                    #         for record in log.records():
                    #             event = record.lxml()
                    #             soup = BeautifulSoup(
                    #                 etree.tostring(event), features="xml"
                    #             )
                    #             print(soup.find("TimeCreated").get("SystemTime"))  # type: ignore
                    #             payload = {"event": soup.__str__()}
                    #             await socket.send(
                    #                 message=json.dumps(payload), text=True
                    #             )
                    #             await socket.recv()

                    #     print("reading logs...")
                    # currentchunk = log.get_file_header().current_chunk()
                    # await readandsendlog(currentchunk)
                    def receive_event(action, context, event_handle):
                        if action == win32evtlog.EvtSubscribeActionDeliver:
                            event = win32evtlog.EvtRender(
                                Event=event_handle, Flags=win32evtlog.EvtRenderEventXml
                            )
                            soup = BeautifulSoup(event, features="xml")
                            payload = {"event": soup.__str__()}
                            q.put(payload)
                            # loop.run_until_complete(future=send_evt())

                    handle = EvtSubscribe(
                        ChannelPath="Microsoft-Windows-Sysmon/Operational",
                        Flags=win32evtlog.EvtSubscribeToFutureEvents,
                        Callback=receive_event,
                    )

                    async def send_socket_worker():
                        async def send_evt(payload):
                            await socket.send(message=json.dumps(payload), text=True)
                            await socket.recv()

                        payload = q.get()
                        await send_evt(payload=payload)
                        print("sent")

                    while True:
                        await send_socket_worker()
                        # header = log.get_file_header()
                        # await readandsendlog(log)
            except websockets.exceptions.ConnectionClosed as e:
                print("diconnected exception: " + e.__str__())
                print("attempting reconnection")
                continue
            except Exception as e:
                print("critical: " + e.__str__())
                break
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
