from Evtx import Evtx
from os import path, environ
from robocopy import robocopy
from requests import post

def main():
    sysmon_dest_path = path.join(environ['USERPROFILE'], 'Desktop', 'sysmon')
    sysmon_file_name = 'Microsoft-Windows-Sysmon%4Operational.evtx'
    sysmon_src_path = path.abspath('C:\Windows\System32\winevt\Logs')
    try: 
        robocopy.copy(sysmon_src_path, sysmon_dest_path, sysmon_file_name)
        with Evtx.Evtx(filename=path.join(sysmon_dest_path, sysmon_file_name)) as log:
            header = log.get_file_header()
            print('<Events>')
            for record in log.records():
                payload = {"event": record.xml()}
                post('http://127.0.0.1:8000/api/event', data = payload)
                break
            print('</Events>')

        
        
    except Exception as e:
        print(f"Error: {e}")
    

        

    


if __name__ == "__main__":
    main()
