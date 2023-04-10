from cortex4py.api import Api
from cortex4py.query import *
import os
import sys
import json
import time

cortex_app_url = os.environ['CORTEX_APP_URL']
cortex_api_key = os.environ['CORTEX_API_KEY']
api = Api(cortex_app_url, cortex_api_key)


observable_template = {
    'data': 'google.com',
    'dataType': 'domain',
    'tlp': 1,
}

def send_to_cortex(api):
    try:
        # Implicitly test cortex connection by finding all available analyzers.
        print("[cortex.py] Available analyzers: %s" % api.analyzers.find_all({}, range='all'), file=sys.stderr, flush=True)
        for observable_raw in sys.stdin:
            observable = json.loads(observable_raw.rstrip())
            # Get enabled analyzers
            scoped_analyzers = api.analyzers.get_by_type(observable["type"])
            jobs = []
            for analyzer in scoped_analyzers:
                # Schedule analysis job
                jobs.append(api.analyzers.run_by_name(analyzer.workerDefinitionId, {
                    "data": observable["value"],
                    "dataType": observable["type"],
                    "tlp": 1
                    }))
            for job in jobs:
                # Retrieve job report
                report = api.jobs.get_report_async(job_id=job.id, timeout="10minute").json()
                #report["report"]["value"] = observable["value"]
                # keep raw_log as required by the scheduler
                observable["full"] = report["report"]["full"]
                #report["report"]["raw_log"] = observable["raw_log"]
                #print("[cortex.py %s] %s" % (job.workerDefinitionId, json.dumps(observable)), file=sys.stderr, flush=True)
                print("%s" % json.dumps(observable), flush=True)
    except Exception as e:
        print("[cortex.py] %s" % e, file=sys.stderr, flush=True)
        if e != "'full'":
            # exception was not about a failed report
            time.sleep(1)
            sys.stdout.close()
            return

send_to_cortex(api)


