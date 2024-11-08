#!/usr/bin/env python3
import schedule
import time
import netbox_sync
from datetime import datetime


def main():
    lTime = datetime.now()
    print(f'Start Sheduler work {lTime.strftime("%c")}')
    schedule.every(6).hours.do(netbox_sync.main)
 
#
    while True:
        schedule.run_pending()
        time.sleep(10)

if __name__ == "__main__":
    main()
else:
    print("Please execute this program as main\n")
