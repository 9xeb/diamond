import regex as re
import sys
#import re
import json
import threading
import hashlib
from subprocess import Popen, PIPE, STDOUT
#import subprocess
from itertools import combinations
import time

from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, text, select, update, delete
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.sql import text
from sqlalchemy_views import CreateView, DropView

from pymispwarninglists import WarningLists

from datetime import datetime, timedelta

from functools import lru_cache
from cachetools import cached, TTLCache
from bisect import bisect_left, bisect_right


# sqlalchemy ORM magic
Base = declarative_base()
class Iocs(Base):
    __tablename__ = 'iocs'
    value = Column(Text, primary_key = True)
    type = Column(Text)
    #events = Column(Integer)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    #timestamp = Column(Datetime) useful for detecting unique iocs that haven't been seen in a while and for time based anomaly detection in general
class IocsHosts(Base):
    __tablename__ = 'iocs_hosts'
    ioc_value = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key=True)
    host = Column(Text, primary_key=True)
class IocsTags(Base):
    __tablename__ = 'iocs_tags'
    name = Column(Text, primary_key = True)
    description = Column(Text)
    evil = Column(Boolean)
    confidence = Column(Integer)
class IocsBonds(Base):
    __tablename__ = 'iocs_bonds'
    ioc1 = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key = True)
    ioc2 = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key = True)
    strength = Column(Integer)
class IocsTaggings(Base):
    __tablename__ = 'iocs_taggings'
    ioc = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key=True)
    tag = Column(Text, ForeignKey('iocs_tags.name'), primary_key=True)
class ExternalVectorInternal(Base):
    __tablename__ = 'external_vector_internal'
    external = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key=True)
    vector = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key=True)
    internal = Column(Text, ForeignKey('iocs.value', ondelete="CASCADE"), primary_key=True)


# Ingest single line of text, extract ioc(s), update SQL database, repeat
class IocCorrelationEngine():
    def __init__(self, parsers_config, targets_config, db_engine, db_session, db_lock):

        self.diamond_filename = "/threatintel/data/diamond.log"
        self.tags_filename = "/threatintel/data/tags.log"

        # IOCs last unseen for more than 60 days are deleted
        self.ioc_ttl = timedelta(days=60)
        # Default warning lists
        #self.warninglists = WarningLists(slow_search=True)
        self.ioc_cache = []
        self.cache_ttl = 600

        # User configuration
        self.parsers = parsers_config
        #self.units = units_config
        self.targets = targets_config
        #self.db_lock = threading.Lock()
        self.db_lock = db_lock
        self.fatal_event = threading.Event()

        # Database setup
        #self.db_engine = create_engine('sqlite:////threatintel/data/threatintel.db')
        #self.db_session_factory = sessionmaker(bind=self.db_engine)
        #self.db_session = scoped_session(self.db_session_factory)
        #self.db_meta = MetaData()
        self.db_engine = db_engine
        self.db_session = db_session
        self.db_meta = MetaData()

        #self.subprocs = subprocs
        self.subprocs = { key: Popen(self.targets[key]["path"], stdin=PIPE, stdout=PIPE) for key in self.targets.keys() }



        # weighted supposes that the more we see a malicious related ioc, the more it is likely to be malicious. This is not true at all since a single malicious connection might be the source of an entire intrusion
        ioc_scores_view = Table('iocs_related_tags', self.db_meta)
        #test_definition = text("SELECT * FROM iocs")
        ioc_related_tags = text("SELECT ioc1, ioc2, tag, ioc AS tag_source, strength AS tag_strength FROM iocs_tags INNER JOIN iocs_taggings ON iocs_tags.name = iocs_taggings.tag INNER JOIN iocs_bonds ON iocs_taggings.ioc = iocs_bonds.ioc1 OR iocs_taggings.ioc = iocs_bonds.ioc2")
        #ioc_scores_definition = text("SELECT * FROM iocs_bonds INNER JOIN iocs_taggings ON (iocs_bonds.ioc1 = iocs_taggings.ioc OR iocs_bonds.ioc2 = iocs_taggings.ioc) WHERE iocs_taggings.ioc NOT IN (SELECT iocs_taggings.ioc FROM iocs_taggings WHERE iocs_taggings.tag = 'whitelist')")
        
        ioc_correlated_tags_view = Table('iocs_correlated_tags', self.db_meta)
        ioc_correlated_tags = text('SELECT iocs.value, iocs_taggings.ioc, iocs_taggings.tag, iocs_bonds.strength FROM iocs INNER JOIN iocs_bonds ON iocs.value = iocs_bonds.ioc1 INNER JOIN iocs_taggings ON iocs_taggings.ioc = iocs_bonds.ioc2 UNION SELECT iocs.value, iocs_taggings.ioc, iocs_taggings.tag, iocs_bonds.strength FROM iocs INNER JOIN iocs_bonds ON iocs.value = iocs_bonds.ioc2 INNER JOIN iocs_taggings ON iocs_taggings.ioc = iocs_bonds.ioc1')
        
        with self.db_lock:
            # Create ioc tables
            Base.metadata.create_all(self.db_engine)
            #print("[ioc] Lock", file=sys.stderr, flush=True)
            try:
                ioc_scores_create_view = CreateView(ioc_scores_view, ioc_related_tags)
                self.db_engine.execute(ioc_scores_create_view)
            except Exception as e:
                print("DATABASE WARNING: %s" % e, file=sys.stderr, flush=True)
            try:
                iocs_correlated_tags_create_view = CreateView(ioc_correlated_tags_view, ioc_correlated_tags)
                self.db_engine.execute(iocs_correlated_tags_create_view)
            except Exception as e:
                print("DATABASE WARNING: %s" % e, file=sys.stderr, flush=True)
            #print("[!] %s" % str(ioc_scores_create_view.compile()).strip(), file=sys.stderr, flush=True)
        
        print("[ioc] Making sure dummy ioc is present", file=sys.stderr, flush=True)
        with self.db_session() as session:
            if len(session.execute(select(Iocs).where(Iocs.value == '')).all()) == 0:
                session.add(Iocs(value = '', type = None, first_seen = None, last_seen = None))
            session.commit()
            
        #print("[ioc] Unlock", file=sys.stderr, flush=True)

    def update_iocs(self, ioc, timestamp):
        # TODO: turn this into assert + try/except
        with self.db_session() as session:
            if len(session.execute(select(Iocs).where(Iocs.value == ioc['value'])).all()) == 0:
                try:
                    session.add(Iocs(value = ioc['value'], type = ioc['type'], first_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f'), last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')))
                except Exception:
                    # sometimes timestamps come without milliseconds
                    session.add(Iocs(value = ioc['value'], type = ioc['type'], first_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'), last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')))
            else:
                try:
                    session.connection().execute(update(Iocs).where(Iocs.value == ioc['value']), [{"last_seen": datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')}])
                    #print("[ioc] Updating timestamp for %s (1)" % ioc['value'], file=sys.stderr, flush=True)
                except Exception:
                    session.connection().execute(update(Iocs).where(Iocs.value == ioc['value']), [{"last_seen": datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')}])
                    #print("[ioc] Updating timestamp for %s (2)" % ioc['value'], file=sys.stderr, flush=True)
                # 
                #session.up
            #print("[ioc] %s" % ioc['value'], file=sys.stderr, flush=True)
            #print("[%s] [trigger] Add new ioc: %s" % (timestamp, ioc['value']), file=sys.stderr, flush=True)
            session.commit()
    
    def flush_iocs(self):
        #for ioc in session.execute(select(Iocs).where(Iocs.value == io))
        with self.db_session() as session:
            session.execute(delete(Iocs).where(Iocs.last_seen < datetime.now() - self.ioc_ttl))
            #print("[iocs] Flushing iocs where last_seen is older than %s" % (datetime.now() - self.ioc_ttl), file=sys.stderr, flush=True)
            session.commit()
        pass

    def update_iocs_hosts(self, ioc, host):
        with self.db_session() as session:
            if len(session.execute(select(IocsHosts).where(IocsHosts.ioc_value == ioc['value'], IocsHosts.host == host)).all()) == 0:
                session.add(IocsHosts(ioc_value = ioc['value'], host = host))
            session.commit()

    def update_iocs_tags(self, ioc, timestamp):
        with self.db_session() as session:
            for ioc_tag in ioc['tags']:
                if len(session.execute(select(IocsTags).where(IocsTags.name == ioc_tag['value'])).all()) == 0:
                    session.add(IocsTags(name = ioc_tag['value'], description = "No description", evil = ioc_tag['evil'], confidence = 100))
                    print("[ioc] New tag in database (%s : %s)" % (ioc_tag['value'], ioc_tag['evil']), file=sys.stderr, flush=True)
                if len(session.execute(select(IocsTaggings).where(IocsTaggings.ioc == ioc['value'], IocsTaggings.tag == ioc_tag['value'])).all()) == 0:
                    session.add(IocsTaggings(ioc = ioc['value'], tag = ioc_tag['value']))
                    #print("[ioc] Applied tag to %s (%s : %s)" % (ioc['value'], ioc_tag['value'], ioc_tag['evil']), file=sys.stderr, flush=True)
                with open(self.tags_filename, "a") as logfile, self.db_lock:
                    print("%s" % json.dumps({"ts": timestamp, "indicator": ioc['value'], "tag": ioc_tag["value"]}), file=logfile, flush=True)
            session.commit()
    
    def update_iocs_tags_logs(self, ioc, timestamp):
        for ioc_tag in ioc['tags']:
            with open(self.tags_filename, "a") as logfile, self.db_lock:
                print("%s" % json.dumps({"ts": timestamp, "indicator": ioc['value'], "tag": ioc_tag["value"]}), file=logfile, flush=True)

    def update_iocs_bonds(self, iocs, timestamp):
        #iocs.sort()  # sorting is extensively used in place of triggers in sql, so that the primary key tuples' elements order does not matter and database integrity is preserved
        combos = list(combinations(iocs,2))
        for ioc in iocs:
            # add self referencing combos
            combos.append((ioc,ioc))
        sorted_combos = [tuple(sorted(combo)) for combo in combos]
        for combo in sorted_combos:
            #print("[%s] [abusech] binding (%s,%s)" % (timestamp, combo[0], combo[1]), file=sys.stderr, flush=True)
            with self.db_session() as session:
                rows = session.execute(select(IocsBonds.strength).where(IocsBonds.ioc1 == combo[0], IocsBonds.ioc2 == combo[1])).all()
                if len(rows) == 0:
                    session.add(IocsBonds(ioc1 = combo[0], ioc2 = combo[1], strength = 1))
                    print("[bond] %s <-> %s" % (combo[0], combo[1]), file=sys.stderr, flush=True)
                    #dbcursor.execute("INSERT INTO iocs_bonds values (?, ?, ?)", (combo[0], combo[1], 1))
                else:
                    session.query(IocsBonds).filter(IocsBonds.ioc1 == combo[0], IocsBonds.ioc2 == combo[1]).update({IocsBonds.strength: IocsBonds.strength + 1})
                    #print("[%s] [binder] %s <-> %s" % (timestamp, combo[0], combo[1]), file=sys.stderr, flush=True)
                    #dbcursor.execute("UPDATE iocs_bonds set strength=? where ioc1=? and ioc2=?", (rows[0][0]+1, combo[0], combo[1]))
                session.commit()
        #dbconn.commit()

    def update_diamond(self, iocs):
        # split all iocs into three big categories according to the diamond model
        externals = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] == 'ip' or ioc['type'] == 'domain') and 'whitelist' not in ioc['tags']]
        internals = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] == 'ip' or ioc['type'] == 'domain') and 'whitelist' in ioc['tags']]
        vectors = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] != 'ip' and ioc['type'] != 'domain')]
        two_empty_condition = (not externals and not internals) or (not externals and not vectors) or (not internals and not vectors)
        #print("[diamond] externals: %s" % externals, file=sys.stderr, flush=True)
        #print("[diamond] internals: %s" % internals, file=sys.stderr, flush=True)
        #print("[diamond] vectors: %s" % vectors, file=sys.stderr, flush=True)
        # check if at least two instances of the categories are not empty
        if not two_empty_condition:
            externals = ['']  if len(externals) == 0 else externals
            internals = ['']  if len(internals) == 0 else internals
            vectors = ['']  if len(vectors) == 0 else vectors
            with self.db_session() as session:
                for external in externals:
                    for internal in internals:
                        for vector in vectors:
                            rows = session.execute(select(ExternalVectorInternal).where(ExternalVectorInternal.external == external, ExternalVectorInternal.vector == vector, ExternalVectorInternal.internal == internal)).all()
                            if len(rows) == 0:
                                session.add(ExternalVectorInternal(external = external, vector = vector, internal = internal))
                                print("[diamond] (%s, %s, %s)" % (external, vector, internal), file=sys.stderr, flush=True)
                            #with open(self.diamond_filename, "a") as logfile, self.db_lock:
                            #    print("%s" % json.dumps({"ts": iocs['timestamp'], "external": external, "vector": vector, "internal": internal}), file=logfile, flush=True)
                session.commit()
        else:
            #print("[diamond] At least two instances are empty, skipping diamond", file=sys.stderr, flush=True)
            pass
        #time.sleep(5)
        return

    def update_diamond_logs(self, iocs):
        # split all iocs into three big categories according to the diamond model
        externals = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] == 'ip' or ioc['type'] == 'domain') and 'whitelist' not in ioc['tags']]
        internals = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] == 'ip' or ioc['type'] == 'domain') and 'whitelist' in ioc['tags']]
        vectors = [ioc['value'] for ioc in iocs['iocs'] if (ioc['type'] != 'ip' and ioc['type'] != 'domain')]
        two_empty_condition = (not externals and not internals) or (not externals and not vectors) or (not internals and not vectors)
        # check if at least two instances of the categories are not empty
        if not two_empty_condition:
            externals = ['']  if len(externals) == 0 else externals
            internals = ['']  if len(internals) == 0 else internals
            vectors = ['']  if len(vectors) == 0 else vectors
            with open(self.diamond_filename, "wa") as logfile, self.db_lock:
                for external in externals:
                    for internal in internals:
                        for vector in vectors:
                            payload = {"ts": iocs['timestamp'], "external": external, "vector": vector, "internal": internal}
                            if not self.diamond_cache_hit(payload):
                                print("%s" % json.dumps({"ts": iocs['timestamp'], "external": external, "vector": vector, "internal": internal}), file=logfile, flush=True)
        #else:
        #    print("[diamond] At least two instances are empty, skipping diamond", file=sys.stderr, flush=True)
        #time.sleep(5)
        return



    def get_log_id(self, log):
        # compute log id by hashing its own data
        logstring = "%s,%s,%s" % (log['host'], log['program'], log['line'])
        return hashlib.sha256(logstring.encode()).hexdigest()


  # TODO: sqlite3.IntegrityError except, instead of generic Exception. This way we can filter out expected integrity errors from actual malfunctioning

    def expire_ioc_tags(self, ioc):
        with self.db_session() as session:
            session.execute(delete(IocsTags).where(IocsTags.name == ioc['value']))
            session.execute(delete(IocsTaggings).where(IocsTaggings.ioc == ioc['value']))
            #print("[ioc] Expired tags for %s" % (ioc['value']), file=sys.stderr, flush=True)
            session.commit()


    def extract_and_process_iocs(self, entry, correlate):
        #print("[ioc] %s" % entry['line'], file=sys.stderr, flush=True)
        # flush expired IOCs
        self.flush_iocs()

        #log = self.parse_elastic_response(entry)
        # cached method
        iocs = self.extract_iocs(json.dumps(entry))

        for ioc in iocs['iocs']:
            if not self.ioc_cache_hit(ioc['value']):
                # ioc is not in cache, refresh tags and all
                self.update_iocs(ioc, entry['timestamp'])
                #self.update_iocs_hosts(ioc, entry['host'])
                if correlate:
                    self.expire_ioc_tags(ioc)
                    self.send_ioc_to_handler(iocs['timestamp'], ioc['value'], ioc['type'], ('whitelist' in ioc['tags']))
                # CAUTION: if handlers take more time than self.cache_ttl, the next self.update_iocs might corrupt entries for handlers' responses
        
        # this replaces the iocs_bonds logic with a better grounded hypothesis
        self.update_diamond(iocs)
        #self.update_diamond_logs(iocs)
        # since the diamond model is a superset of iocs_bonds, we don't need these below
        #self.update_iocs_bonds([ioc['value'] for ioc in iocs['iocs']], entry['timestamp'])
        return iocs


    #@cached(cache=TTLCache(maxsize=None, ttl=600))
    #@lru_cache(maxsize=256)
    def extract_iocs(self, log_json):
        log = json.loads(log_json)
        observable_json = {"log_id": log['id'], "timestamp": log['timestamp'], "host": log['host']}#, "program": log['program']}
        observable_json["iocs"] = []
        #for requested_type in requested_types:
        for requested_type in self.parsers.keys():
            # Some default keys. They can be overwritten by the observable type.
            match = {}
            matched_observables = []
            try:
                # try json parsing first
                classified_logline = json.loads(log['line'])
                for json_keyslist in self.parsers[requested_type]["format"]["matches"]["json"]:
                    matched_observable = classified_logline.copy()
                    try:
                        for key in json_keyslist:
                            matched_observable = matched_observable[key]
                        if matched_observable not in matched_observables:
                            matched_observables.append(matched_observable)
                    except Exception:
                        continue
            except:
                #pass
                # alternatively, use regex on the whole document
                classified_logline = log['line']
                for format in self.parsers[requested_type]["format"]["matches"]["raw"]:
                    for matched_object in re.finditer(format, log['line']):
                        matched_observable = matched_object[0]
                        if matched_observable not in matched_observables:
                            matched_observables.append(matched_observable)

            # for each extracted ioc, whitelist and/or warninglist it
            for matched_observable in matched_observables:
                #matched_warninglists = self.warninglists.search(matched_observable)
                tagged_observable = {'value': matched_observable, 'type': requested_type, 'tags': []}
                if tagged_observable['type'] in ['md5', 'sha1', 'sha256']:
                    # to lowercase if hash, so they are all leveled out
                    tagged_observable['value'] = tagged_observable['value'].lower()
                if ("whitelist" in self.parsers[requested_type]["format"]) and (re.search(self.parsers[requested_type]["format"]["whitelist"], matched_observable)):
                    # whitelisted observables are just skipped
                    tagged_observable['tags'].append('whitelist')
                observable_json["iocs"].append(tagged_observable)                                    
        return observable_json


    def ioc_cache_hit(self, ioc):
        curtime = time.time()
        self.ioc_cache = [value for value in self.ioc_cache if curtime - value['time'] < self.cache_ttl]
        if ioc in (ioc['value'] for ioc in self.ioc_cache):
            #print("[ioc] Cache hit (%s)" % ioc, file=sys.stderr, flush=True)
            return True
        self.ioc_cache.append({'value': ioc, 'time': curtime})
        self.ioc_cache = sorted(self.ioc_cache, key=lambda entry: entry['value'])
        #print("[ioc] Cache miss (%s)" % ioc, file=sys.stderr, flush=True)
        return False
    
    def diamond_cache_hit(self, payload):
        payload_hash = str(hash(json.dumps(payload, sort_keys=True)))
        curtime = time.time()
        self.diamond_cache = [value for value in self.diamond_cache if curtime - value['time'] < self.cache_ttl]
        if payload_hash in (ioc['value'] for ioc in self.diamond_cache):
            #print("[ioc] Cache hit (%s)" % ioc, file=sys.stderr, flush=True)
            return True
        self.diamond_cache.append({'value': payload_hash, 'time': curtime})
        self.diamond_cache = sorted(self.diamond_cache, key=lambda entry: entry['value'])
        #print("[ioc] Cache miss (%s)" % ioc, file=sys.stderr, flush=True)
        return False


    #@lru_cache(maxsize=65535)
    #@cached(cache=TTLCache(maxsize=65535, ttl=600))
    def send_ioc_to_handler(self, timestamp, ioc, type, is_whitelisted):
        for target in self.parsers[type]['target']:
            # TODO: move warninglist to a separate handler
            tags = [{'value': 'whitelist', 'evil': False}] if (is_whitelisted) else []
            self.subprocs[target].stdin.write(bytes(json.dumps({'timestamp': timestamp, 'iocs': [{'value': ioc, 'type': type, 'tags': tags}]})+"\n", 'ascii'))
            #print("[ioc] Sent %s to %s" % (ioc, target), file=sys.stderr, flush=True)
            self.subprocs[target].stdin.flush()
        return True


    def start(self):
        try:
            handlers_response_parsers_threads = []
            for subproc_key in self.subprocs.keys():
                # for each handler subprocess, spawn the relative worker output manager thread
                if subproc_key is None:
                    print("%s worker subprocess failed to launch" % subproc_key, file=sys.stderr, flush=True)
                    return
                thread = threading.Thread(target=self.parse_handlers_response, args=(subproc_key, subproc_key))
                # when the main threads ends, the program will exit even if some 'daemon' threads are running
                thread.daemon = True
                thread.start()
                handlers_response_parsers_threads.append(thread)
                print("%s worker output thread launched" % subproc_key, file=sys.stderr, flush=True)
            # return handle that triggers when ioc engine threads fail
            return self.fatal_event
        except Exception as e:
            print("%s" % e, file=sys.stderr, flush=True)


    # For each handler, read its output line by line, match triggers
    def parse_handlers_response(self, source, subproc_key):
        print("[worker %s] started " % (source), file=sys.stderr, flush=True)
        try:
            for line in iter(self.subprocs[subproc_key].stdout.readline, b''):
                try:
                    decoded_line = line.decode('ascii').rstrip()
                    analysis_response = json.loads(decoded_line)

                    #iocs_list = [ioc['value'] for ioc in analysis_response['iocs']]
                    #with self.db_lock:
                    #print("[trigger] lock: %s" % lock, file=sys.stderr, flush=True)
                    #init_db_tables(dbconn, dbcursor)       
                    #dbconn.commit()
                    #print("[%s] [trigger] %s" % (analysis_response['timestamp'], iocs_list), file=sys.stderr, flush=True)
                    #continue
                    #for ioc in analysis_response['iocs']:
                    #print("[response] %s" % json.dumps(analysis_response, indent=4), file=sys.stderr, flush=True)
                    for ioc in analysis_response['iocs']:
                        # check if value is not already present
                    #    self.update_iocs(ioc, analysis_response['timestamp'])
                    #    self.update_iocs_hosts(ioc, analysis_response['host'])
                        #print("[ioc] Received handler response: %s" % ioc, file=sys.stderr, flush=True)
                        try:
                            self.update_iocs_tags(ioc, analysis_response['timestamp'])
                            self.update_iocs_tags_logs(ioc, analysis_response['timestamp'])
                            #print("[debug] tags for %s -> %s" % (ioc['value'], ioc['tags']), file=sys.stderr, flush=True)
                        except Exception as e:
                            print("[response] Invalid tags in %s (%s)" % (ioc, e), file=sys.stderr, flush=True)
                            continue
                        #self.update_iocs_context(ioc, analysis_response['log_id'], analysis_response['timestamp'], dbconn, dbcursor)
                        #print("[%s] [pusher] %s" % (analysis_response['timestamp'], ioc), file=sys.stderr, flush=True)
                    #self.update_iocs_bonds(iocs_list, analysis_response['timestamp'])

                    # apply a policy that decides which goes directly to crowdsec for remediation (ip and domain only for now)
                except Exception as e:
                    # failed to parse single line (should never happen but it is not fatal, for easier debugging)
                    print("[worker %s] %s" % (source, e), file=sys.stderr, flush=True)
        except Exception:
            # db connection failed
            self.fatal_event.set()
        #out.close()
        print("[worker %s] closed" % source, file=sys.stderr, flush=True)