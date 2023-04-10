#import requests
#import urllib3
#import json
#import sys
#import time
#import threading

from handler import Handler
import sys
import json
import time

class Abusech(Handler):
    def fetch(self, delay):
        try:
            print("[handler.py] fetcher thread is running", file=sys.stderr, flush=True)
            while True:
                try:
                    #data = {
                    #    'query': 'get_iocs',
                    #    'days': days
                    #}
                    #json_data = json.dumps(data)
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
                #for observable in observables:
                    try:
                        #print("[abusech.py] %s" % json.dumps(observable, indent=4), file=sys.stderr, flush=True)
                        #observable['tags'].append('good')
                        with self.lock:
                            index = self.compare_ioc(observable['value'])
                            assert index != -1
                            # TODO: send only if confidence=100
                            observable['tags'].append({'value': self.iocs_list[index]['threat_type'], 'evil': True})
                            #print("[abusech.py] %s matched in %s" % (observable['value'], observables['iocs']), file=sys.stderr, flush=True)
                            print("[abusech.py] %s matched in %s" % (observable['value'], observables), file=sys.stderr, flush=True)
                            print("%s" % json.dumps(observable), flush=True)
                    except Exception as e:
                        #observable['tags'].append('abusech-ok-%s' % observables['timestamp'])
                        #print("[%s] [abusech.py] %s not found" % (observables['timestamp'], observable['value']), file=sys.stderr, flush=True)
                        continue
                print("%s" % json.dumps(observables), flush=True)
            except Exception as e:
                print("[abusech.py] Input is not a valid json", file=sys.stderr, flush=True)


abusech = Abusech(
    'threatfox-api.abuse.ch',
    'POST',
    '/api/v1/',
    {'query': 'get_iocs', 'days': 1},
    'ioc')
abusech.match()
exit()
