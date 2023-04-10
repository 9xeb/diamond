#import requests
import urllib3
import json
import sys
import time
import threading


# TODO: improve error handling in case the handler crashes
class Handler:
    def __init__(self, hostname, request_method="GET", request_endpoint="/", request_body=None, ioc_key='ioc', delay=3600):
        self.lock = threading.Lock()
        self.iocs_list = {}
        self.first_fetch = threading.Event()
        self.pool = urllib3.HTTPSConnectionPool(hostname, port=443, maxsize=50, cert_reqs='CERT_NONE', assert_hostname=True)
        self.hostname = hostname
        self.body = request_body
        self.method = request_method
        self.endpoint = request_endpoint
        self.key = ioc_key
        
        thread = threading.Thread(target=self.fetch, args=[delay])
        thread.daemon = True
        thread.start()

    # thread function that:
    #   1. retrieves ioc list
    #   2. sorts it for easier searching when matching
    #   3. self.first_fetch.set()
    # this is done differently in any case
    def fetch(self, delay):
        return

    # matches and incoming ioc with entries in self.iocs_list
    # this works fine in most cases, as long as self.iocs_list is a list of dictionaries and self.key is defined
    def match(self):
        return

    def compare_ioc(self, ioc):
        def compare_ioc_aux(iocs, ioc, inf, sup):
            if inf > sup:
                return -1
            mid=int((inf+sup)/2)
            if ioc > iocs[mid][self.key]:
                return compare_ioc_aux(iocs, ioc, mid+1, sup)
            elif ioc < iocs[mid][self.key]:
                return compare_ioc_aux(iocs, ioc, inf, mid-1)
            else:
                return mid
        return compare_ioc_aux(self.iocs_list, ioc, 0, len(self.iocs_list))

    def debug(self):
        while True:
            with self.lock:
                for value in self.iocs_list:
                    print("%s" % json.dumps(value, indent=4), file=sys.stderr, flush=True)
                    time.sleep(0.5)
            time.sleep(3)
