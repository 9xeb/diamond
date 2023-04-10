#!/usr/bin/python3.8

#os.environ['CORTEX_APP_URL']
from hashlib import new
import os
import sys
import json
from datetime import datetime
import redis
import time
import statistics

class BehaviorMemory:
    def __init__(self, behaviors={}, redis_hostname="localhost", redis_port="6379", redis_pwd=""):
        # BehaviorMemory is divided into chucks. Each chunk is N seconds of behavior recording. They are stored in a redis database.
        # Chunks should be big enough to contain anomalous bursts and small enough to be stored in large quantities (several weeks or months)
        # Single chunks can be used for anomalous burst detection, and groups of chunks are gathered for comparative anomaly analysis.
        self.behaviors_chunk = behaviors
        self.redis = redis.Redis(redis_hostname, redis_port, redis_pwd)
        self.redis_key_prefix = "user-behavior"
    
    def update_counter(self, observable):
        try:
            redis_key = "%s:%s:%s" % (self.redis_key_prefix, observable["actor"], observable["tag"])
            redis_record = self.redis.get(redis_key)
            if redis_record is None:
                self.redis.set(redis_key, 1)
            else:
                self.redis.set(redis_key, redis_record + 1)            
        except Exception as e:
            print("[BehaviorAnalysisException] %s" % e, file=sys.stderr, flush=True)
    
    def dump_outliers(self):
        try:
            for key in self.redis.keys(pattern="%s" % self.redis_key_prefix):
                redis_record = self.redis.get(key)


        except Exception as e:
            return

try:
    bm = BehaviorMemory(redis_hostname=os.environ['REDIS_HOSTNAME'])
    print("[behavior-analytics] Behavior memory initialized", file=sys.stderr, flush=True)
    for behavior in sys.stdin:
        new_behavior = json.loads(behavior.rstrip())
        bm.update_memory(new_behavior)
        #print(json.dumps(new_behavior), flush=True)
except Exception as e:
    print("[BehaviorMemoryException] %s" % e, file=sys.stderr, flush=True)

