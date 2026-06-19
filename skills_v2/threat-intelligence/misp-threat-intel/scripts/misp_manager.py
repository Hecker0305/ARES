#!/usr/bin/env python3
"""MISP Threat Intelligence Manager"""
import argparse
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject
except ImportError:
    logger.error("pymisp not installed. Install with: pip install pymisp")
    exit(1)

class MISPManager:
    def __init__(self, url: str, api_key: str, ssl: bool = True):
        self.misp = ExpandedPyMISP(url, api_key, ssl=ssl)

    def create_event(self, info: str, threat_level: int = 2, analysis: int = 1, distribution: int = 1) -> str:
        event = MISPEvent()
        event.info = info
        event.threat_level_id = threat_level
        event.analysis = analysis
        event.distribution = distribution
        response = self.misp.add_event(event, pythonify=True)
        logger.info(f"Created event {response.id}: {info}")
        return response.id

    def add_ioc(self, event_id: str, category: str, ioc_type: str, value: str, comment: str = ""):
        attr = MISPAttribute()
        attr.category = category
        attr.type = ioc_type
        attr.value = value
        attr.comment = comment
        attr.to_ids = True
        self.misp.add_attribute(event_id, attr)
        logger.info(f"Added {ioc_type}: {value} to event {event_id}")

    def search_iocs(self, days: int = 7, limit: int = 100) -> List[Dict]:
        date_from = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')
        events = self.misp.search_index(limit=limit, datefrom=date_from)
        iocs = []
        for event in events:
            event_data = self.misp.get_event(event['id'])
            for attr in event_data['Event']['Attribute']:
                iocs.append({
                    'event_id': event['id'],
                    'event_info': event['info'],
                    'category': attr['category'],
                    'type': attr['type'],
                    'value': attr['value'],
                    'timestamp': attr['timestamp']
                })
        return iocs

    def export_stix(self, event_id: str = None) -> str:
        if event_id:
            return json.dumps(self.misp.get_event(event_id))
        return json.dumps(self.misp.export_all(return_format='json'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='MISP instance URL')
    parser.add_argument('--api-key', required=True, help='MISP API key')
    parser.add_argument('--action', required=True, choices=['create_event', 'add_ioc', 'search', 'export'])
    parser.add_argument('--event-info', help='Event description for create_event')
    parser.add_argument('--event-id', help='Event UUID')
    parser.add_argument('--category', help='Attribute category')
    parser.add_argument('--ioc-type', help='Attribute type')
    parser.add_argument('--ioc-value', help='Attribute value')
    args = parser.parse_args()
    manager = MISPManager(args.url, args.api_key)
    if args.action == 'create_event':
        eid = manager.create_event(args.event_info or 'New event')
        print(json.dumps({'event_id': eid}))
    elif args.action == 'search':
        iocs = manager.search_iocs()
        print(json.dumps(iocs, indent=2))
    elif args.action == 'export':
        print(manager.export_stix(args.event_id))
