#from handler import Handler
import sys
import json
import time
import threading
import urllib3

class Rstcloud():
    def __init__(self, hostname, request_method="GET", request_endpoint="/", request_body=None, ioc_key=['ioc'], delay=3600):
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

    def fetch(self, delay):
        try:
            print("[handler.py] fetcher thread is running", file=sys.stderr, flush=True)
            while True:
                try:
                    time.sleep(2)
                    if self.body is not None:
                        response = self.pool.request(self.method, self.endpoint, body=json.dumps(self.body))
                    else:
                        response = self.pool.request(self.method, self.endpoint)
                    response = response.data.decode("utf-8", "ignore")
                    with self.lock:
                            print("[handler.py] Sorting IOCs list by key: %s" % self.key, file=sys.stderr, flush=True)
                            self.iocs_list = sorted(json.loads(response)['data'], key=lambda ioc_json: ioc_json[self.key])
                    print("[handler.py] IOCs list updated, next update in %s seconds" % delay, file=sys.stderr, flush=True)
                    self.first_fetch.set()
                    time.sleep(delay)
                except Exception as e:
                    print("[handler.py] ERROR: unable to %s at https://%s%s (json). Retrying in 5 seconds" % (self.method, self.hostname, self.endpoint), file=sys.stderr, flush=True)
                    time.sleep(5)
                    continue
        except Exception as e:
            print("[handler.py] ERROR %s" % e, file=sys.stderr, flush=True)

    def match(self):
        print("[abusech.py] Matcher thread is waiting for first fetch to happen", file=sys.stderr, flush=True)
        self.first_fetch.wait()
        print("[abusech.py] Matcher thread is running", file=sys.stderr, flush=True)
        for observables_raw in sys.stdin:
            try:
                #print("[abusech.py] %s" % observables_raw, file=sys.stderr, flush=True)
                #continue
                observables = json.loads(observables_raw.rstrip())
                #type = observable['type']
                #value = observable['value']
                for observable in observables['iocs']:
                    try:
                        #print("[abusech.py] %s" % json.dumps(observable, indent=4), file=sys.stderr, flush=True)
                        #observable['tags'].append('good')
                        with self.lock:
                            index = self.compare_ioc(observable['value'])
                            assert index != -1
                            # TODO: send only if confidence=100
                            observable['tags'].append(self.iocs_list[index]['threat_type'])
                            print("[%s] [abusech.py] %s matched in %s" % (observables['timestamp'], observable['value'], observables['iocs']), file=sys.stderr, flush=True)
                            print("%s" % json.dumps(observable), flush=True)
                    except Exception as e:
                        #observable['tags'].append('abusech-ok-%s' % observables['timestamp'])
                        print("[%s] [abusech.py] %s not found" % (observables['timestamp'], observable['value']), file=sys.stderr, flush=True)
                        continue
                print("%s" % json.dumps(observables), flush=True)
            except Exception as e:
                print("[%s] [abusech.py] Input is not a valid json" % observables['timestamp'], file=sys.stderr, flush=True)


rstcloud = Rstcloud(
    'rstcloud.net',
    'GET',
    '/free/ioc/ioc_ip_latest.json',
    None,
    ['ip', 'v4'])
rstcloud = Rstcloud(
    'rstcloud.net',
    'GET',
    '/free/ioc/ioc_domain_latest.json',
    None,
    ['domain'])
rstcloud = Rstcloud(
    'rstcloud.net',
    'GET',
    '/free/ioc/ioc_url_latest.json',
    None,
    ['url'])
rstcloud = Rstcloud(
    'rstcloud.net',
    'GET',
    '/free/ioc/ioc_hash_latest.json',
    None,
    ['ip', 'v4'])
rstcloud = Rstcloud(
    'raw.githubusercontent.com',
    'GET',
    '/rstcloud/rstthreats/master/feeds/hacker_tools_hashes.json',
    None,
    [['md5'], ['sha1'], ['sha256']])

for observables_raw in sys.stdin:
    rstcloud.match()
exit()

'''
https://rstcloud.net/free/ioc/ioc_ip_latest.json
https://rstcloud.net/free/ioc/ioc_domain_latest.json
https://rstcloud.net/free/ioc/ioc_url_latest.json
https://rstcloud.net/free/ioc/ioc_hash_latest.json
https://raw.githubusercontent.com/rstcloud/rstthreats/master/feeds/hacker_tools_hashes.json
'''