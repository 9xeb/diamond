from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from datetime import datetime, timedelta
import sys
import time
import json
import os

# Thanks to https://github.com/AlienVault-OTX/OTX-Python-SDK
class OTXHandler():
    def __init__(self, apikey, delay):
        self.otx = OTXv2(apikey)
        self.delay = delay

    def is_too_old(self, pulse_time, days_limit):
        pulse_time = datetime.strptime(pulse_time, '%Y-%m-%dT%H:%M:%S.%f')
        return datetime.now() - pulse_time > timedelta(days_limit, 0)

    def is_from_subscribed_or_followed(self, pulse):
        return pulse['author']['is_following'] or pulse['author']['is_subscribed']


    def search_ioc(self, type, value, days_limit):
        alerts = []

        result = self.otx.get_indicator_details_by_section(type, value, 'general')
        if len(result['validation']) == 0:
            for pulse in result['pulse_info']['pulses']:
                old = days_limit != 0 and self.is_too_old(pulse['modified'], days_limit)
                if (not old) and self.is_from_subscribed_or_followed(pulse):
                    if pulse['name'] not in alerts:
                        alerts.append({'value': pulse['name'], 'evil': True})
                    #for attack_id in pulse['attack_ids']:
                    #    if attack_id['display_name'] not in alerts:
                    #        alerts.append({'value': attack_id['display_name'], 'evil': True})
                        #if attack_id['id'] not in alerts:
                            #alerts.append({'value': attack_id['id'], 'evil': True})
                        #if attack_id['name'] not in alerts:
                            #alerts.append({'value': attack_id['name'], 'evil': True})
        return alerts
        
    def search_ip(self, ip):
        alerts = []
        return self.search_ioc(IndicatorTypes.IPv4, ip, 90)

        result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        if len(result['validation']) == 0:
            for pulse in result['pulse_info']['pulses']:
                if (not self.is_too_old(pulse['modified'])) and self.is_from_subscribed_or_followed(pulse):
                    if pulse['description'] not in alerts:
                        alerts.append({'value': pulse['description'], 'evil': True})
                    for attack_id in pulse['attack_ids']:
                        if attack_id['id'] not in alerts:
                            alerts.append({'value': attack_id['id'], 'evil': True})
                        if attack_id['name'] not in alerts:
                            alerts.append({'value': attack_id['name'], 'evil': True})
        return alerts


        result_malware = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'malware')
        if len(result_malware['data']) > 0:
            alerts.append({'value': 'otx-malware', 'evil': True})
        return alerts
        

        try:
            alerts.append({'value': result['country_name'], 'evil': False})
            if len(result['validation']) == 0:
                # not a known false positive
                for pulse in result['pulse_info']['pulses']:
                    if pulse['name'] not in alerts:
                        alerts.append({'value': pulse['name'], 'evil': True})
        except Exception as e:
            print("[otx] Not matched (%s)" % e, file=sys.stderr, flush=True)
        return alerts


    def search_hostname(self, hostname):
        alerts = []
        hostname_analysis = self.search_ioc(IndicatorTypes.HOSTNAME, hostname, 90)
        domain_analysis = self.search_ioc(IndicatorTypes.DOMAIN, hostname, 90)
        return list(set(hostname_analysis + domain_analysis))

        # Check both as hostname and domain
        for result in [self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general'), self.otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')]:
        #result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')
            #if len(result['data']) > 0:
            #    if 'otx-malware' not in (alert['value'] for alert in alerts):
            #        alerts.append({'value': 'otx-malware', 'evil': True})
            #continue
            if len(result['validation']) == 0:
                for pulse in result['pulse_info']['pulses']:
                    if (not self.is_too_old(pulse['modified'])) and self.is_from_subscribed_or_followed(pulse):
                        if pulse['description'] not in alerts:
                            alerts.append({'value': pulse['description'], 'evil': True})
                        for attack_id in pulse['attack_ids']:
                            if attack_id['id'] not in alerts:
                                alerts.append({'value': attack_id['id'], 'evil': True})
                            if attack_id['name'] not in alerts:
                                alerts.append({'value': attack_id['name'], 'evil': True})
        return alerts


    def search_url(self, url):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.URL, url)
        #result = self.otx.get_indicator_details_by_section(IndicatorTypes.URL, url, 'url_list')
        #print("%s" % json.dumps(result, indent=4))

        google = result['url_list']['url_list']['result']['safebrowsing'] #getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'value': 'google-safebrowsing', 'evil': True})


        clamav = result['url_list']['url_list']['result']['multiav']['matches']['clamav'] #getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
        if clamav:
            alerts.append({'value': 'clamav', 'evil': True})

        avast = result['url_list']['url_list']['result']['multiav']['matches']['avast'] #getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
        if avast:
            alerts.append({'value': 'avast', 'evil': True})

        # Todo: Check file page
        return alerts

        # Get the file analysis too, if it exists
        has_analysis = result['url_list']['url_list']['result']['urlworker']['has_file_analysis'] #getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'has_file_analysis'])
        if has_analysis:
            hash = result['url_list']['url_list']['result']['urlworker']['sha256'] #getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
            file_alerts = file(self.otx, hash)
            if file_alerts:
                for alert in file_alerts:
                    alerts.append(alert)



    def search_file_hash(self, hash):
        alerts = []

        # Identify hash by length
        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1
        
        #result = self.otx.get_indicator_details_full(hash_type, hash)
        return self.search_ioc(hash_type, hash, 90)

        try:
            # plugins
            plugins = result['analysis']['analysis']['plugins']
            if len(plugins['avg']['results']['detection']) > 0:
                #alerts.append(plugins['avg']['results']['detection'])
                alerts.append({'value': 'avg', 'evil': True})
        except:
            #print("[otx] avg not found", file=sys.stderr, flush=True)
            ""
        try:
            if len(plugins['clamav']['results']['detection']) > 0:
                #alerts.append(plugins['clamav']['results']['detection'])
                alerts.append({'value': 'clamav', 'evil': True})
        except:
            #print("[otx] clamav not found", file=sys.stderr, flush=True)
            ""
        try:
            if len(plugins['avast']['results']['detection']) > 0:
                #alerts.append(plugins['avast']['results']['detection'])
                alerts.append({'value': 'avast', 'evil': True})
        except:
            #print("[otx] avast not found", file=sys.stderr, flush=True)
            ""
        #try:
        #    if len(plugins['msdefender']['results']['detection']) > 0:
                #alerts.append(plugins['msdefender']['results']['detection'])
        #        alerts.append({'value': 'msdefender', 'evil': True})
        #except:
            #print("[otx] msdefender not found", file=sys.stderr, flush=True)
        #    ""
        #try:
        #    if len(plugins['adobemalwareclassifier']['results']['alerts']) > 0:
        #        alerts.append({'value': 'adobemalwareclassifier', 'evil': True})
                #for alert in plugins['adobemalwareclassifier']['results']['alerts']:
                #    alerts.append(alert)
        #except:
            #print("[otx] adobemalwareclassifier not found", file=sys.stderr, flush=True)
        #    ""
        # virustotal
        try:
            virustotal = plugins['cuckoo']['result']['virustotal']['scans']
            if len(virustotal['Microsoft']['result']) > 0:
                #alerts.append(virustotal['Microsoft']['result'])
                alerts.append({'value': 'cuckoo/microsoft', 'evil': True})
        except:
            #print("[otx] cuckoo/microsoft not found", file=sys.stderr, flush=True)
            ""
        try:
            if len(virustotal['Symantec']['result']) > 0:
                #alerts.append(virustotal['Symantec']['result'])
                alerts.append({'value': 'cuckoo/symantec', 'evil': True})
        except:
            #print("[otx] cuckoo/symantec not found", file=sys.stderr, flush=True)
            ""
        try:
            if len(virustotal['Kaspersky']['result']) > 0:
                #alerts.append(virustotal['Kaspersky']['result'])
                alerts.append({'value': 'cuckoo/kaspersky', 'evil': True})
        except:
            #print("[otx] cuckoo/kaspersky not found", file=sys.stderr, flush=True)
            ""

        try:
            suricata = plugins['cuckoo']['result']['suricata']['rules']['name']
            if len(suricata) > 0 and 'trojan' in str(suricata).lower():
                alerts.append({'value': 'cuckoo/suricata', 'evil': True})
                #alerts.append(suricata)
        except:
            #print("[otx] suricata not found", file=sys.stderr, flush=True)
            ""
        #print("%s" % json.dumps(result, indent=4))  
        return alerts
        # avg


    def search(self, ioc, type):
        print("[otx] %s (%s)" % (ioc, type), file=sys.stderr, flush=True)
        if type == 'ip':
            result = self.search_ip(ioc)
        elif type == 'domain':
            result = self.search_hostname(ioc)
        elif type == 'md5' or type == 'sha1' or type == 'sha256':
            result = self.search_file_hash(ioc)
        elif type == 'url':
            result = self.search_url(ioc)
        else:
            result = []
        return result


    def match(self):
        for observables_raw in sys.stdin:
            observables = json.loads(observables_raw.rstrip())
            #print("[match] %s" % json.dumps(observables, indent=4), file=sys.stderr, flush=True)
            for observable in observables['iocs']:
                try:
                    #print("[match] %s %s" % (observable['value'], observable['type']), file=sys.stderr, flush=True)
                    observable['tags'] = self.search(observable['value'], observable['type'])
                    if len(observable['tags']) > 0:
                        print("[otx] %s matched in otx" % observable['value'], file=sys.stderr, flush=True)
                except Exception as e:
                    #continue
                    print("[otx] %s" % e, file=sys.stderr, flush=True)
            #print("[otx-result] %s" % json.dumps(observables), file=sys.stderr, flush=True)
            print("%s" % json.dumps(observables), flush=True)
            time.sleep(self.delay)


handler = OTXHandler(os.environ['OTX_API_KEY'], 0.5)
handler.match()