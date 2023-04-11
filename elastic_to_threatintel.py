#!/usr/bin/python3.8

# After syslog.sh. Schedule to IOC analyzer or user behaviour in a multithreaded way

# The workflow: syslog.sh -> schedule.py -> ioc-analyze.sh -> publish.sh
#                                        |
#                                        -> user-behaviour.py ->

import os
import sys
import threading
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
#from elasticsearch_follow import ElasticsearchFollow, Follower
import time
import json
import ioc_correlation_engine
#import sigma_engine
#import sigma_engine
from datetime import datetime, timedelta
import hashlib
import requests

from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, ForeignKey, text, select, update
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from threading import Lock

# sqlalchemy ORM magic
Base = declarative_base()
#class Logs(Base):
#    __tablename__ = 'logs'
    #id = Column(Integer, primary_key = True)
    #timestamp = Column(String)
    #host = Column(String)
    #program = Column(String)
    #message = Column(String)

class ParserScheduler:
    def __init__(self, parsers_config, targets_config):
        #self.subprocs = { key: Popen(self.targets[key]["path"], stdin=PIPE, stdout=PIPE) for key in self.targets.keys() }  
        self.nlogs = 0      

        try:
            self.elasticsearch_host = os.environ['ELASTIC_HOST']
            #self.elasticsearch_index = os.environ['ELASTIC_INDEX']
            self.elasticsearch_indexes = ['filebeat-*', 'winlogbeat-*']
            self.elasticsearch_username = os.environ['ELASTIC_USER']
            self.elasticsearch_password = os.environ['ELASTIC_PASSWORD']
            # Test elasticsearch connection before proceeding
            self.es = Elasticsearch(['%s' % self.elasticsearch_host], http_auth=(self.elasticsearch_username, self.elasticsearch_password))
            if not self.es.ping():
                # Docs mention something about an info() interface to get the actual reason why a ping failed. Might be useful to print that out too.
                print("[elastic] Failed to connect to %s" % self.elasticsearch_host, file=sys.stderr, flush=True)
                raise Exception("[elastic] Failed to connect to %s" % self.elasticsearch_host)
            for index in self.elasticsearch_indexes:
                if not self.es.indices.exists(index=index):
                    print("[elastic] Index %s does not exist in elastic" % index, file=sys.stderr, flush=True)
                    raise Exception("[elastic] Index %s does not exist in elastic" % index)
            self.elasticsearch_disabled = False
        except:
            self.elasticsearch_disabled = True
            print("[parser] Elasticsearch queries are disabled.", file=sys.stderr, flush=True)
        self.time_zone = os.environ['LOGS_TIMEZONE_OFFSET']

        self.db_user = os.environ['DB_USER']
        self.db_password = os.environ['DB_PASSWORD']
        #self.db_host = os.environ['DB_HOST']
        
        # this way, stderr of each process is printed by this script for debugging.
        # this does not affect normal operation between the scheduler and the workers, since it is done in stdin/stdout
        # spawn handler subprocesses

        # Database setup
        #self.db_engine = create_engine('sqlite:////threatintel/data/threatintel.db')
        #self.db_engine = create_engine('mysql+pymysql://%s:%s@database:3306/threatintel' % (self.db_user, self.db_password))
        self.db_engine = create_engine('postgresql+psycopg2://%s:%s@threatintel-database/threatintel' % (self.db_user, self.db_password))
        self.db_session_factory = sessionmaker(bind=self.db_engine)
        self.db_session = scoped_session(self.db_session_factory)
        self.db_lock = threading.Lock()
        #self.db_meta = MetaData()

        # Create log tables
        Base.metadata.create_all(self.db_engine)

        ####self.sigma_engine = sigma_engine.SigmaRunner(rules_pattern = '/queries/', time_target = 60, db_engine=self.db_engine, db_session=self.db_session, db_lock=self.db_lock)
        #self.sigma_engine = sigma_engine.SigmaRunner(rules_pattern = '/sigma/rules/**/*.es', time_target = 60, db_engine=self.db_engine, db_session=self.db_session, db_lock=self.db_lock)

        # this must be placed last because some initialization queries somehow ignore db_lock
        self.ioc_engine = ioc_correlation_engine.IocCorrelationEngine(parsers_config, targets_config, self.db_engine, self.db_session, self.db_lock)

        self.query_interval = 30
        self.parser_stats = {}
        self.parser_stats_interval = 100
        self.print_lock = Lock()
    
    # apply mask to a dictionary and see if it matches
    # this is especially useful to decide if an observable is malicious based on json reports coming from observable handlers
    def dict_match(self, dict1, mask):
            # WARNING: this has one big limitation: it cannot traverse lists. This means that masks are only allowed to have lists in the leaves
            decision = True
            try:
                if dict1 == mask or dict1 in mask:
                    print("Matched %s in %s " % (dict1, mask), file=sys.stderr, flush=True)
                    return True
                else:
                    print("Failed to match %s in %s " % (dict1, mask), file=sys.stderr, flush=True)
                    return False
            except Exception as e:
                # Compute intersection of keys at the current level
                # Check for missing mask keys in the intersection
                # Ignore this process if mask is not a dictionary, so leaves in the form of lists can be matched below
                inters = set(dict1).intersection(set(mask))

                left = set(mask).difference(inters)

                if len(left) > 0:
                        # Some mask keys are left unmatched, meaning the mask cannot be applied

                        return False
                for name in inters:

                        decision = decision and self.dict_match(dict1[name], mask[name])
                # the decision flag holds info coming from oracles and the current depth level aswell
                return decision

    def keys_match(self, dict, keys_list):
        #check if key structure from dict2 is inside dict1
        for key in keys_list:
            if key not in dict:
                return False
            else:
                dict = dict[key]
        return True

    def parse_elasticsearch_logs(self):
        #print("[parser] Targets: %s" % self.subprocs.keys(), file=sys.stderr, flush=True)

        # need to let elasticsearch store documents before we query them, so the cursor is kept at least self.query_interval behind real-time
        left_time = datetime.now() - timedelta(0, self.query_interval * 2)
        right_time = datetime.now() - timedelta(0, self.query_interval)

        ##es_follow = ElasticsearchFollow(elasticsearch=self.es)
        ##follower = Follower(elasticsearch_follow=es_follow, index=self.elasticsearch_index, time_delta=60)
        #print("%s" % self.es.info(), file=sys.stderr, flush=True)

        with open("/threatintel/data/elasticsearch.log", "w") as logfile:
            # TODO: save right_time to file in order to survive restarts
            while True:
                right_timestring = right_time.strftime("%Y-%m-%dT%H:%M:%S")
                left_timestring = left_time.strftime("%Y-%m-%dT%H:%M:%S")
                range_query_for_scan = {
                "query": {
                    "bool": {
                        "must": [
                            {
                            "range": {
                                "@timestamp": {
                                    "gte": left_timestring,
                                    "lt": right_timestring,
                                    #"format": "strict_date_optional_time"
                                    }
                                }
                            }
                        ]
                    }
                }
                }
                print("[elastic] Querying from %s to %s" % (left_timestring, right_timestring), file=sys.stderr, flush=True)
                try:
                    #print("[parser] Generator restored", flush=True)
                    #entries = follower.generator()
                    for index in self.elasticsearch_indexes:
                        try:
                            #resp = self.es.search(index=index, query=range_query)
                            #print("[elastic] %s returned %s documents (page %s long)" % (index, resp['hits']['total']['value'], len(resp['hits']['hits'])), file=sys.stderr, flush=True)
                            #scan_generator = scan(self.es, index=index, query=range_query_for_scan3)
                            #scan_results = [hit for hit in scan_generator]
                            #print("[elastic] %s returned %s documents" % (index, len(scan_results)), file=sys.stderr, flush=True)
                            #for hit in resp['hits']['hits']:
                            for hit in scan(self.es, index=index, query=range_query_for_scan):
                                try:
                                    log_entry = hit['_source']
                                    #print("[parser] %s" % json.dumps(log_entry), file=sys.stderr, flush=True)
                                    parsed_log = self.parse_elasticsearch_response(log_entry)
                                    if parsed_log['program'] not in self.parser_stats.keys():
                                        self.parser_stats[parsed_log['program']] = 0
                                    else:
                                        self.parser_stats[parsed_log['program']] += 1
                                    self.ioc_engine.extract_and_process_iocs(entry = parsed_log, correlate = True)
                                    #self.ioc_engine.extract_iocs(entry = log_entry, correlate = True)
                                    self.nlogs+=1
                                    if self.nlogs == self.parser_stats_interval:
                                        #print("[parser] Parsed %s logs" % self.nlogs, file=sys.stderr, flush=True)
                                        print("[elasticsearch] %s" % json.dumps(self.parser_stats, indent=4), file=sys.stderr, flush=True)
                                        self.nlogs = 0
                                    
                                    #with self.print_lock:
                                    #    print("%s threatintel %s[1] %s" % (datetime.strptime(log_entry['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%b %d %H:%M:%S"), 
                                    #                                        parsed_log['program'], 
                                    #                                        parsed_log['line']), file=logfile, flush=True)
                                    #datetime.strptime(log_entry['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%b %d %H:%M:%S")
                                    
                                except Exception as e:
                                    # every time a regex is not matched it gets here. This happens quite often as someone would expect.
                                    print("[scheduler-error] %s [%s]" % (e, json.dumps(log_entry)), file=sys.stderr, flush=True)# An unexpected json is simply skipped, this usually means a record of a declared service name did not match the entire regex chain
                                    #time.sleep(5)
                                    continue
                        except Exception as e:
                            print("Unable to query %s index (%s)" % (index, e), file=sys.stderr, flush=True)
                except Exception as e:
                    print("[parser] %s" % e, file=sys.stderr, flush=True)
                #print("[parser] Generator depleted", file=sys.stderr, flush=True)
                left_time = right_time
                time.sleep(self.query_interval)

                # try to keep up with elapsed time
                right_time = datetime.now() - timedelta(0, self.query_interval)
                #right_time = left_time + timedelta(0, self.query_interval)

    def parse_stdin_logs(self):
        number_of_logs = 0
        with open("/threatintel/data/stdin.log", "w") as logfile:
            for line in sys.stdin:
                log_entry = line.rstrip()
                parsed_log = {}
                parsed_log['line'] = log_entry
                parsed_log['timestamp'] = str(datetime.now()) # .strftime("%Y-%m-%d %H:%M:%S")
                parsed_log['host'] = 'unknown'
                parsed_log['program'] = 'unknown'
                #parsed_log['id'] = self.get_log_id(parsed_log)
                parsed_log['id'] = 0
                #print("[stdin] Parsed line: %s" % log_entry, file=sys.stderr, flush=True)
                number_of_logs += 1
                if number_of_logs == self.parser_stats_interval:
                    print("[stdin] Parsed %s logs from stdin" % number_of_logs, file=sys.stderr, flush=True)
                self.ioc_engine.extract_and_process_iocs(entry = parsed_log, correlate = True)

                #with self.print_lock:
                #    print("%s threatintel %s[1] %s" % (datetime.strptime(parsed_log['timestamp'], "%Y-%m-%d %H:%M:%S").strftime("%b %d %H:%M:%S"), 
                #                                        parsed_log['program'], 
                #                                        parsed_log['line']), file=logfile, flush=True)

    def parse_elasticsearch_response(self, entry):
        #id = entry['_id']
        #print("[sigma-parse] %s" % json.dumps(entry), file=sys.stderr, flush=True)
        #time.sleep(5)
        logtimestamp = str(datetime.strptime(entry['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ'))    # minor conversion from filebeat @timestamp to integrate with sql datetime type
        loghost = "%s" % entry['agent']['hostname']
        try:
            logprogram = "%s" % entry['process']['name']
        except Exception:
            logprogram = "%s" % entry['event']['module']
            
        # each input line usually follows the pattern: {@timestamp} {host[hostname]} {process[name]} {message}
        try:
            logline = "%s" % (entry['event']['original'])
        except Exception:
            try:
                logline = "%s" % (entry['message'])
            except Exception:
                # if all else fails, turn the entire json from elastic into a string, and use that to extract observables
                logline = json.dumps(entry)
                #print("[%s] [sigma-parser] Parser had to fallback to json dumps (source: %s)" % (logtimestamp, logprogram),  file=sys.stderr, flush=True)
        log = {'timestamp': logtimestamp, 'host': loghost, 'program': logprogram, 'line': logline}
        log['id'] = self.get_log_id(log)
        return log
    
    def parse_stdin_response(self, entry):
        try:
            # attempt to delegate to ioc_engine as json
            self.ioc_engine.extract_and_process_iocs(entry = json.dumps(json.loads(entry)), correlate = True)
        except:
            # fallback to non-json log string
            self.ioc_engine.extract_and_process_iocs(entry = entry, correlate = True)



    def get_log_id(self, log):
        # compute log id by hashing its own data
        logstring = "%s,%s,%s" % (log['host'], log['program'], log['line'])
        return hashlib.sha256(logstring.encode()).hexdigest()

    
    def start(self):
        try:
            self.ioc_engine.start()
            ####self.sigma_engine.start()

            # spawn elasticsearch parser thread
            if not self.elasticsearch_disabled:
                parser_thread = threading.Thread(target=self.parse_elasticsearch_logs)
                parser_thread.daemon = True
                parser_thread.start()
                print("[elasticsearch] Parser thread for elasticsearch launched", file=sys.stderr, flush=True)

            # spawn stdin parser thread
            parser_thread = threading.Thread(target=self.parse_stdin_logs)
            parser_thread.daemon = True
            parser_thread.start()
            print("[stdin] Parser thread for stdin launched", file=sys.stderr, flush=True)
            
            # wait for a fatal error to happen (typically a handler not working)
            print("[main] Main thread is ready and waiting for a fatal error to happen", file=sys.stderr, flush=True)
            self.ioc_engine.fatal_event.wait()
            print("[main] Fatal error happened", file=sys.stderr, flush=True)
            for target_keys in self.targets.keys():
                # for each handler subprocess, terminate it
                self.subprocstargets_subprocesses[target_keys].terminate()
                print("[main] Terminated subprocess %s" % target_keys, file=sys.stderr, flush=True)
            return
        except Exception as e:
            print("%s" % e, file=sys.stderr, flush=True)



# targets can be strings or functions
# dictionaries are treated as paths to executables and expected environment variables
targets_json = {
#    "cortex": {
#        "path": ["python3", "./handlers/cortex.py"],
#        "env": {
#            "CORTEX_APP_URL": os.environ['CORTEX_APP_URL'],
#            "CORTEX_API_KEY": os.environ['CORTEX_API_KEY']
#        },
#        "check": ""
#    },
    "abusech": {
        "path": ["python3", "/threatintel/handlers/abusech.py"]
    },
    "misp-warninglist": {
        "path": ["python3", "/threatintel/handlers/misp-warninglist.py"]
    },
    #"alienvault-otx": {
    #    "path": ["python3", "/threatintel/handlers/alienvault-otx.py"]
    #}
#    "behavior-analytics": {
#        "path": ["python3", "./handlers/user-behavior.py"],
#        "env": {}
#    }
}


observable_patterns = {
    "ip": r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",
    "port": r"\d{1,5}\b",
    "domain": r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
    "md5": r'[0-9a-fA-F]{32}'
}

# "target" keys are mapped to the targets dictionary
parsers_json = {
    "ip": {
        "format": {
            "matches": {
                "raw": [r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"],
                "json": [["src_ip"], ["dest_ip"]]
            },
            #"whitelist": "(^224\.0\.0\.|^0\.|^192\.168\.|^127\.|^255\.255\.255\.255|^10\.)"
            "whitelist": "(10\.[0-9]{1,3}|127\.[0-9]{1,3}|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)(\.[0-9]{1,3}){2}"
        },
        "target": ["abusech", "misp-warninglist"]
    },
    "ip:port": {
        "format": {
            "matches": {
                "raw": [r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}:\d{1,5}\b"],
                "json": [["src_ip:src_port"], ["dst_ip:dst_port"]]
            }
        },
        "target": ["abusech"]
    },
    #"ip-port": {},
    "domain": {
        "format": {
            "matches": {
                "raw": [r'(?<![0-9a-zA-Z.])((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+'],
                #"raw": [r'(?<![0-9a-zA-Z])((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}(?![0-9a-zA-Z])'],
                #"raw": [r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'],
                #"json": [["dns", "rrname"]]
            },
            "whitelist": "(.local$|.leandojo$|^pi.hole$)"
        },
        "target": ["abusech", "misp-warninglist"]
    },
    "md5": {
        "format": {
            "matches": {
                "raw": [r'(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])']
            }
        },
        "target": ["abusech", "misp-warninglist"]
    },
    "sha1": {
        "format": {
            "matches" : {
                "raw": [r'(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])']
            }
        },
        "target": ["abusech", "misp-warninglist"]
    },
    "sha256": {
        "format": {
            "matches" : {
                "raw": [r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])']
            }
        },
        "target": ["abusech", "misp-warninglist"]
    },
    "url": {
        "format": {
            "matches": {
                "raw": [r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+']
            }
        },
        "target": ["abusech", "misp-warninglist"]
    }
}


"suricata:ip pnat:ip dnsmasq\[.*\].*query:domain netpot:ip audisp-syslog:behavior"
units_json = {
    #"*": ["ip", "ip:port", "domain", "md5", "sha1", "sha256"],
    "suricata": ["ip", "ip:port", "domain", "md5", "sha1", "sha256", "url"],
    "pnat": ["ip"],
#    "dnsmasq\[.*\].*query\[A": ["domain"],
    "netpot": ["ip"]
#    "audisp-syslog": ["behavior"]
}

resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
uppercase_tlds = "|".join([tld.upper() for tld in bytes(resp.content).decode('utf-8').split('\n') if not tld.startswith("#") and tld != ''])
lowercase_tlds = "|".join([tld.lower() for tld in bytes(resp.content).decode('utf-8').split('\n') if not tld.startswith("#") and tld != ''])
#print("%s" % uppercase_tlds, file=sys.stderr, flush=True)
#print("%s" % lowercase_tlds, file=sys.stderr, flush=True)
parsers_json['domain']['format']['matches']['raw'][0] += "(" + uppercase_tlds + "|" + lowercase_tlds + ")" + '(?![0-9a-zA-Z.])'
#parsers_json['domain']['format']['matches']['raw'] += "(" + "|".join([tld for tld in bytes(resp.content).decode('utf-8').split('\n') if not tld.startswith("#") and tld != '']) + ")"
print("%s" % (parsers_json['domain']['format']['matches']['raw']), file=sys.stderr, flush=True)
#exit()

# initialize parser
parser_scheduler = ParserScheduler(parsers_json, targets_json)
try:
    parser_scheduler.start()
except Exception as e:
    print("[FATAL] parser-scheduler will stop now %s" % e, file=sys.stderr, flush=True)
    time.sleep(3)
    exit()
