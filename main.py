import websockets
from Evtx import Evtx
from os import path, environ
from lxml import etree
from robocopy import robocopy
from requests import Session, post
from time import sleep
from bs4 import BeautifulSoup
import asyncio
import json


async def main():
    sysmon_dest_path = path.join(environ['USERPROFILE'], 'Desktop', 'sysmon')
    sysmon_file_name = 'Microsoft-Windows-Sysmon%4Operational.evtx'
    sysmon_src_path = path.abspath('C:\\Windows\\System32\\winevt\\Logs')
    keyword = ['whoami', 'tasklist', 'quser']
    extension = ['.bat', '.cmd', '.rar']
    try: 
        async with websockets.connect("ws://127.0.0.1:8000/ws") as socket:
            while True:
                robocopy.copy(sysmon_src_path, sysmon_dest_path, sysmon_file_name)
                with Evtx.Evtx(filename=path.join(sysmon_dest_path, sysmon_file_name)) as log:
                    # header = log.get_file_header()
                    for record in log.records():
                        event = record.lxml()
                        soup = BeautifulSoup(etree.tostring(event), features="xml")    
                        payload = {"event": soup.__str__()}
                        await socket.send(message=json.dumps(payload), text= True)
                        break
                    break
                    sleep(30)
                break

        
        
    except Exception as e:
        print(f"Error: {e}")
    

        

    


if __name__ == "__main__":
    asyncio.run(main())
