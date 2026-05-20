from Evtx import Evtx
from os import path, environ

def main():
    try:
        with Evtx.Evtx(filename=path.join(environ['USERPROFILE'], 'Desktop', 'sysmon', 'Microsoft-Windows-Sysmon%4Operational.evtx')) as log:
            header = log.get_file_header()
            print('<Events>')
            for record in log.records():
                print(record.xml())
            print('</Events>')

        
        
    except Exception as e:
        print(f"Error: {e}")
    

        

    


if __name__ == "__main__":
    main()
