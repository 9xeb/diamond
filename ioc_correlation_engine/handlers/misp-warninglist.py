from pymispwarninglists import WarningLists
import sys
import json

class MispWarninglist():
    def __init__(self):
        self.warninglists = WarningLists(slow_search=True)    
    
    def match(self):
        for observables_raw in sys.stdin:
            observables = json.loads(observables_raw.rstrip())
            for observable in observables['iocs']:
                try:
                    matched_warninglists = self.warninglists.search(observable['value'])
                    for hit in matched_warninglists:
                        observable['tags'].append({'value': hit.name, 'evil': False})
                    if len(matched_warninglists) > 0:
                        observable['tags'].append({'value': 'warninglist', 'evil': False})
                        #print("[warninglist] %s is in warninglist" % observable['value'], file=sys.stderr, flush=True)
                except Exception as e:
                    print("[misp-warninglist] %s" % e, file=sys.stderr, flush=True)
            print("%s" % json.dumps(observables), flush=True)

mispwarninglist = MispWarninglist()
mispwarninglist.match()