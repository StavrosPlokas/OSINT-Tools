#!/usr/bin/env python3
"""
OSINT Analysis Tool
Comprehensive threat intelligence analysis for IPs, Domains, Hashes, and URLs
"""

import requests
import json
import re
import time
import hashlib
import socket
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import argparse
import sys

@dataclass
class AnalysisResult:
    """Base class for analysis results"""
    service: str
    status: str
    timestamp: str
    url: Optional[str] = None
    error: Optional[str] = None

@dataclass
class VirusTotalResult(AnalysisResult):
    """VirusTotal analysis result"""
    detections: Optional[int] = None
    total_engines: Optional[int] = None
    scan_date: Optional[str] = None
    positives: Optional[List[str]] = None

@dataclass
class MalwareBazaarResult(AnalysisResult):
    """Malware Bazaar analysis result"""
    family: Optional[str] = None
    tags: Optional[List[str]] = None
    file_type: Optional[str] = None
    signature: Optional[str] = None

@dataclass
class HybridAnalysisResult(AnalysisResult):
    """Hybrid Analysis result"""
    threat_score: Optional[int] = None
    verdict: Optional[str] = None
    environment: Optional[str] = None
    analysis_time: Optional[str] = None

@dataclass
class AnyRunResult(AnalysisResult):
    """Any.run analysis result"""
    family: Optional[str] = None
    behavior: Optional[List[str]] = None
    network_activity: Optional[bool] = None
    file_modifications: Optional[bool] = None

@dataclass
class IPAnalysisResult(AnalysisResult):
    """IP analysis result"""
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    reputation_score: Optional[int] = None
    abuse_confidence: Optional[int] = None
    open_ports: Optional[List[int]] = None

@dataclass
class DomainAnalysisResult(AnalysisResult):
    """Domain analysis result"""
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    subdomains_count: Optional[int] = None
    last_analysis_stats: Optional[int]= None
    last_analysis_results: Optional[str]= None

@dataclass
class URLHausResult(AnalysisResult):
    """URLHaus analysis result"""
    url_id: Optional[str] = None
    date_added: Optional[str] = None
    host: Optional[str] = None
    tags: Optional[List[str]] = None
    payloads: Optional[List[Dict]] = None
    threat_status: Optional[str] = None

class OSINTAnalyzer:
    """Main OSINT Analysis class"""
    
    def __init__(self, config: Dict[str, str] = None):
        """
        Initialize the OSINT Analyzer
        
        Args:
            config: Dictionary containing API keys for various services
                   Expected keys: 'virustotal', 'hybridanalysis', 'shodan', 'urlhaus', etc.
        """
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Analyzer/1.0'
        })
        
        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 1  # seconds
        self.service_intervals = {
            'virustotal': 4.0,  # Four seconds delay for VirusTotal
            'malware_bazaar': 2.0,
            'hybrid_analysis': 5.0,
            'anyrun': 5.0,
            'abuseipdb': 1.5,
            'shodan': 1.0,
            'urlhaus': 2.0,
            'geolocation': 1.0,
            'securitytrails': 2.0
        }
        
    def _rate_limit(self, service: str):
        """Implement rate limiting for API calls"""
        if service in self.last_request_time:
            # Use service-specific interval if available, otherwise use default
            interval = self.service_intervals.get(service, self.min_request_interval)
            elapsed = time.time() - self.last_request_time[service]
            if elapsed < interval:
                time.sleep(interval - elapsed)
        
        self.last_request_time[service] = time.time()
    
    def _detect_input_type(self, input_value: str) -> str:
        """Auto-detect input type (IP, domain, hash, or URL)"""
        input_value = input_value.strip()
        
        # URL detection (starts with http:// or https://)
        if input_value.startswith(('http://', 'https://')):
            return 'url'
        
        # Hash detection (MD5: 32, SHA1: 40, SHA256: 64 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', input_value):
            return 'hash'
        elif re.match(r'^[a-fA-F0-9]{40}$', input_value):
            return 'hash'
        elif re.match(r'^[a-fA-F0-9]{64}$', input_value):
            return 'hash'
        
        # IP detection
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, input_value):
            return 'ip'
        
        # Domain detection
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, input_value):
            return 'domain'
        
        return 'unknown'
    
    def analyze_hash(self, hash_value: str) -> Dict[str, Union[AnalysisResult, None]]:
        """
        Comprehensive hash analysis using multiple services
        
        Args:
            hash_value: Hash to analyze (MD5, SHA1, or SHA256)
            
        Returns:
            Dictionary containing results from different services
        """
        results = {}
        
        # VirusTotal
        try:
            results['virustotal'] = self._virustotal_hash(hash_value)
        except Exception as e:
            results['virustotal'] = AnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        # Malware Bazaar (Requires API key)
        if 'malware_bazaar' in self.config:
            try:
                results['malware_bazaar'] = self._malware_bazaar_hash(hash_value)
            except Exception as e:
                results['malware_bazaar'] = AnalysisResult(
                    service='Malware Bazaar',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    error=str(e)
                )
        else:
            results['malware_bazaar'] = AnalysisResult(
                service='Malware Bazaar',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                error="API key not provided"
            )
        
        # Hybrid Analysis (Skip if no API key)
        if 'hybridanalysis' in self.config:
            try:
                results['hybrid_analysis'] = self._hybrid_analysis_hash(hash_value)
            except Exception as e:
                results['hybrid_analysis'] = AnalysisResult(
                    service='Hybrid Analysis',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    error=str(e)
                )
        else:
            results['hybrid_analysis'] = AnalysisResult(
                service='Hybrid Analysis',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.hybrid-analysis.com/sample/{hash_value}",
                error="API key not provided"
            )
        
        # Any.run (Skip if no API key)
        if 'anyrun' in self.config:
            try:
                results['anyrun'] = self._anyrun_hash(hash_value)
            except Exception as e:
                results['anyrun'] = AnalysisResult(
                    service='Any.run',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    error=str(e)
                )
        else:
            results['anyrun'] = AnalysisResult(
                service='Any.run',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://app.any.run/tasks/?hash={hash_value}",
                error="API key not provided"
            )
        
        return results
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Union[AnalysisResult, None]]:
        """
        Comprehensive IP analysis using multiple services
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            Dictionary containing results from different services
        """
        results = {}
        
        # VirusTotal
        try:
            results['virustotal'] = self._virustotal_ip(ip_address)
        except Exception as e:
            results['virustotal'] = AnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        # AbuseIPDB
        try:
            results['abuseipdb'] = self._abuseipdb_ip(ip_address)
        except Exception as e:
            results['abuseipdb'] = AnalysisResult(
                service='AbuseIPDB',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        # Shodan
        try:
            results['shodan'] = self._shodan_ip(ip_address)
        except Exception as e:
            results['shodan'] = AnalysisResult(
                service='Shodan',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        # IP Geolocation
        try:
            results['geolocation'] = self._ip_geolocation(ip_address)
        except Exception as e:
            results['geolocation'] = AnalysisResult(
                service='IP Geolocation',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Union[AnalysisResult, None]]:
        """
        Comprehensive domain analysis using multiple services
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary containing results from different services
        """
        results = {}
        
        # VirusTotal
        try:
            results['virustotal'] = self._virustotal_domain(domain)
        except Exception as e:
            results['virustotal'] = AnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        # SecurityTrails
        try:
            results['securitytrails'] = self._securitytrails_domain(domain)
        except Exception as e:
            results['securitytrails'] = AnalysisResult(
                service='SecurityTrails',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        return results
    
    def analyze_url(self, url: str) -> Dict[str, Union[AnalysisResult, None]]:
        """
        Comprehensive URL analysis using multiple services
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing results from different services
        """
        results = {}
        
        # URLHaus analysis
        try:
            results['urlhaus'] = self._urlhaus_url(url)
        except Exception as e:
            results['urlhaus'] = AnalysisResult(
                service='URLHaus',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

                # VirusTotal
        try:
            results['virustotal'] = self._virustotal_url(url)
        except Exception as e:
            results['virustotal'] = AnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        
        return results
    
    # VirusTotal API methods
    def _virustotal_hash(self, hash_value: str) -> VirusTotalResult:
        """Query VirusTotal for hash analysis"""
        self._rate_limit('virustotal')
        
        if 'virustotal' not in self.config:
            return VirusTotalResult(
                service='VirusTotal',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/file/{hash_value}",
                error="API key not provided"
            )
        
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': self.config['virustotal'],
            'resource': hash_value
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            # Check if response is empty or not JSON
            if not response.text.strip():
                return VirusTotalResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/file/{hash_value}",
                    error="Empty response from VirusTotal API"
                )
            
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                return VirusTotalResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/file/{hash_value}",
                    error=f"Invalid JSON response: {str(e)[:100]}... (Response: {response.text[:200]}...)"
                )
            
            if data.get('response_code') == 1:
                return VirusTotalResult(
                    service='VirusTotal',
                    status='found',
                    timestamp=datetime.now().isoformat(),
                    url=data.get('permalink'),
                    detections=data.get('positives', 0),
                    total_engines=data.get('total', 0),
                    scan_date=data.get('scan_date'),
                    positives=list(data.get('scans', {}).keys()) if data.get('positives', 0) > 0 else []
                )
            else:
                return VirusTotalResult(
                    service='VirusTotal',
                    status='not_found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/file/{hash_value}"
                )
        except requests.exceptions.RequestException as e:
            return VirusTotalResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/file/{hash_value}",
                error=f"Request failed: {str(e)}"
            )
    
    def _virustotal_ip(self, ip_address: str) -> IPAnalysisResult:
        """Query VirusTotal for IP analysis using API v3"""
        self._rate_limit('virustotal')
        
        if 'virustotal' not in self.config:
            raise ValueError("VirusTotal API key not provided")
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            'x-apikey': self.config['virustotal']
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Check if response is empty or not JSON
            if not response.text.strip():
                return IPAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    error="Empty response from VirusTotal API"
                )
            
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                return IPAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    error=f"Invalid JSON response: {str(e)[:100]}... (Response: {response.text[:200]}...)"
                )
            
            attributes = data.get('data', {}).get('attributes', {})
            
            return IPAnalysisResult(
                service='VirusTotal',
                status='analyzed',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                country=attributes.get('country'),
                reputation_score=attributes.get('reputation', 0),
                abuse_confidence=None
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return IPAnalysisResult(
                    service='VirusTotal',
                    status='not_found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    error="IP address not found in VirusTotal"
                )
            else:
                return IPAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    error=f"HTTP Error {e.response.status_code}: {str(e)}"
                )
        except requests.exceptions.RequestException as e:
            return IPAnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                error=f"Request failed: {str(e)}"
            )
    
    def _virustotal_domain(self, domain: str) -> DomainAnalysisResult:
        """Query VirusTotal for domain analysis using API v3"""
        self._rate_limit('virustotal')
        
        if 'virustotal' not in self.config:
            raise ValueError("VirusTotal API key not provided")
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            'x-apikey': self.config['virustotal']
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Check if response is empty or not JSON
            if not response.text.strip():
                return DomainAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    error="Empty response from VirusTotal API"
                )
            
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                return DomainAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    error=f"Invalid JSON response: {str(e)[:100]}... (Response: {response.text[:200]}...)"
                )
            
            attributes = data.get('data', {}).get('attributes', {})
            
            return DomainAnalysisResult(
                service='VirusTotal',
                status='analyzed',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/domain/{domain}",
                categories=attributes.get('categories', {}),  # v3 returns categories as dict
                registrar=attributes.get('registrar'),
                creation_date=datetime.fromtimestamp(attributes.get('creation_date'), timezone.utc).isoformat(),
                last_analysis_stats=attributes.get('last_analysis_stats', {}),
                
                # Note: subdomains require a separate API call in v3
                #subdomains_count=0  # Would need additional API call to get accurate count
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return DomainAnalysisResult(
                    service='VirusTotal',
                    status='not_found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    error="Domain not found in VirusTotal"
                )
            else:
                return DomainAnalysisResult(
                    service='VirusTotal',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    error=f"HTTP Error {e.response.status_code}: {str(e)}"
                )
        except requests.exceptions.RequestException as e:
            return DomainAnalysisResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/domain/{domain}",
                error=f"Request failed: {str(e)}"
            )
    
    # Malware Bazaar API methods
    def _malware_bazaar_hash(self, hash_value: str) -> MalwareBazaarResult:
        """Query Malware Bazaar for hash analysis"""
        self._rate_limit('malware_bazaar')
        
        if 'malware_bazaar' not in self.config:
            return MalwareBazaarResult(
                service='Malware Bazaar',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                error="API key not provided"
            )
        
        url = "https://mb-api.abuse.ch/api/v1/"
        
        # Malware Bazaar API with authentication
        headers = {
            "Auth-Key": self.config['malware_bazaar']
        }
        
        data = {
            'query': 'get_info',
            'hash': hash_value
        }
        
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result.get('query_status') == 'ok' and result.get('data'):
                sample_data = result['data'][0] if result['data'] else {}
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                    family=sample_data.get('signature'),
                    tags=sample_data.get('tags', []),
                    file_type=sample_data.get('file_type'),
                    signature=sample_data.get('signature')
                )
            elif result.get('query_status') == 'hash_not_found':
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='not_found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}"
                )
            elif result.get('query_status') == 'unauthorized':
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                    error="Invalid API key or unauthorized access"
                )
            else:
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='no_data',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                    error=f"Unexpected response: {result.get('query_status', 'unknown')}"
                )
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                    error="401 Unauthorized - Invalid API key"
                )
            else:
                return MalwareBazaarResult(
                    service='Malware Bazaar',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                    error=f"HTTP Error {e.response.status_code}: {str(e)}"
                )
        except requests.exceptions.RequestException as e:
            return MalwareBazaarResult(
                service='Malware Bazaar',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                error=f"Request failed: {str(e)}"
            )
        except json.JSONDecodeError as e:
            return MalwareBazaarResult(
                service='Malware Bazaar',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://bazaar.abuse.ch/sample/{hash_value}",
                error=f"Invalid JSON response: {str(e)}"
            )
    
    # Hybrid Analysis API methods
    def _hybrid_analysis_hash(self, hash_value: str) -> HybridAnalysisResult:
        """Query Hybrid Analysis for hash analysis"""
        self._rate_limit('hybrid_analysis')
        
        if 'hybridanalysis' not in self.config:
            raise ValueError("Hybrid Analysis API key not provided")
        
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            'api-key': self.config['hybridanalysis'],
            'User-Agent': 'Falcon Sandbox'
        }
        data = {
            'hash': hash_value
        }
        
        response = self.session.post(url, headers=headers, data=data)
        response.raise_for_status()
        results = response.json()
        
        if results:
            data = results[0]
            return HybridAnalysisResult(
                service='Hybrid Analysis',
                status='found',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.hybrid-analysis.com/sample/{hash_value}",
                threat_score=data.get('threat_score'),
                verdict=data.get('verdict'),
                environment=data.get('environment_description')
            )
        else:
            return HybridAnalysisResult(
                service='Hybrid Analysis',
                status='not_found',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.hybrid-analysis.com/sample/{hash_value}"
            )
    
    # Any.run API methods
    def _anyrun_hash(self, hash_value: str) -> AnyRunResult:
        """Query Any.run for hash analysis"""
        self._rate_limit('anyrun')
        
        if 'anyrun' not in self.config:
            raise ValueError("Any.run API key not provided")
        
        url = f"https://api.any.run/v1/analysis"
        headers = {
            'Authorization': f'API-Key {self.config["anyrun"]}'
        }
        params = {
            'hash': hash_value
        }
        
        response = self.session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data'):
            analysis = data['data'][0] if data['data'] else {}
            return AnyRunResult(
                service='Any.run',
                status='found',
                timestamp=datetime.now().isoformat(),
                url=f"https://app.any.run/tasks/?hash={hash_value}",
                family=analysis.get('threat', {}).get('family'),
                behavior=[],  # Would need additional API calls for detailed behavior
                network_activity=analysis.get('scores', {}).get('network', 0) > 0,
                file_modifications=analysis.get('scores', {}).get('file', 0) > 0
            )
        else:
            return AnyRunResult(
                service='Any.run',
                status='not_found',
                timestamp=datetime.now().isoformat(),
                url=f"https://app.any.run/tasks/?hash={hash_value}"
            )
    
    # AbuseIPDB API methods
    def _abuseipdb_ip(self, ip_address: str) -> IPAnalysisResult:
        """Query AbuseIPDB for IP analysis"""
        self._rate_limit('abuseipdb')
        
        if 'abuseipdb' not in self.config:
            raise ValueError("AbuseIPDB API key not provided")
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.config['abuseipdb'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = self.session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']
        
        return IPAnalysisResult(
            service='AbuseIPDB',
            status='analyzed',
            timestamp=datetime.now().isoformat(),
            url=f"https://www.abuseipdb.com/check/{ip_address}",
            country=data.get('countryCode'),
            isp=data.get('isp'),
            abuse_confidence=data.get('abuseConfidencePercentage', 0)
        )
    
    # Shodan API methods
    def _shodan_ip(self, ip_address: str) -> IPAnalysisResult:
        """Query Shodan for IP analysis"""
        self._rate_limit('shodan')
        
        if 'shodan' not in self.config:
            raise ValueError("Shodan API key not provided")
        
        url = f"https://api.shodan.io/shodan/host/{ip_address}"
        params = {
            'key': self.config['shodan']
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        
        return IPAnalysisResult(
            service='Shodan',
            status='analyzed',
            timestamp=datetime.now().isoformat(),
            url=f"https://www.shodan.io/host/{ip_address}",
            country=data.get('country_name'),
            city=data.get('city'),
            isp=data.get('isp'),
            open_ports=[service.get('port') for service in data.get('data', [])]
        )
    
    # IP Geolocation
    def _ip_geolocation(self, ip_address: str) -> IPAnalysisResult:
        """Get IP geolocation information (using free service)"""
        self._rate_limit('geolocation')
        
        url = f"http://ip-api.com/json/{ip_address}"
        
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        
        if data['status'] == 'success':
            return IPAnalysisResult(
                service='IP Geolocation',
                status='analyzed',
                timestamp=datetime.now().isoformat(),
                country=data.get('country'),
                city=data.get('city'),
                isp=data.get('isp')
            )
        else:
            return IPAnalysisResult(
                service='IP Geolocation',
                status='error',
                timestamp=datetime.now().isoformat(),
                error=data.get('message', 'Unknown error')
            )
    
    # Domain analysis methods
    
    def _securitytrails_domain(self, domain: str) -> DomainAnalysisResult:
        """Query SecurityTrails for domain analysis"""
        self._rate_limit('securitytrails')
        
        if 'securitytrails' not in self.config:
            raise ValueError("SecurityTrails API key not provided")
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {
            'APIKEY': self.config['securitytrails']
        }
        
        response = self.session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        return DomainAnalysisResult(
            service='SecurityTrails',
            status='analyzed',
            timestamp=datetime.now().isoformat(),
            url=f"https://securitytrails.com/domain/{domain}",
            subdomains_count=data.get('subdomain_count', 0)
        )

    # URLHaus API methods
    def _urlhaus_url(self, url: str) -> URLHausResult:
        """Query URLHaus for URL analysis"""
        self._rate_limit('urlhaus')
        
        if 'urlhaus' not in self.config:
            return URLHausResult(
                service='URLHaus',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url="https://urlhaus.abuse.ch/",
                error="API key not provided"
            )
        
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {
            "Auth-Key": self.config['urlhaus']
        }
        data = {
            "url": url
        }
        
        try:
            response = self.session.post(api_url, headers=headers, data=data, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            status = result.get("query_status")
            
            if status == "ok":
                payloads = result.get("payloads", []) or []
                processed_payloads = []
                
                if payloads:
                    for payload in payloads:
                        if payload:  # Make sure payload is not None
                            processed_payloads.append({
                                'sha256': payload.get('response_sha256', 'N/A'),
                                'file_type': payload.get('file_type', 'N/A'),
                                'file_size': payload.get('response_size', 'N/A'),
                                'first_seen': payload.get('firstseen', 'N/A')
                            })
                
                # Ensure tags is not None
                tags = result.get('tags', []) or []
                
                return URLHausResult(
                    service='URLHaus',
                    status='found',
                    timestamp=datetime.now().isoformat(),
                    url=f"https://urlhaus.abuse.ch/url/{result.get('id', '')}",
                    url_id=str(result.get('id', 'N/A')),
                    date_added=result.get('date_added', 'N/A'),
                    host=result.get('host', 'N/A'),
                    tags=tags,
                    payloads=processed_payloads,
                    threat_status=result.get('threat', 'N/A')
                )
            elif status == "no_results":
                return URLHausResult(
                    service='URLHaus',
                    status='not_found',
                    timestamp=datetime.now().isoformat(),
                    url="https://urlhaus.abuse.ch/"
                )
            else:
                return URLHausResult(
                    service='URLHaus',
                    status='error',
                    timestamp=datetime.now().isoformat(),
                    url="https://urlhaus.abuse.ch/",
                    error=f"Unexpected query_status: {status}"
                )
                
        except requests.exceptions.RequestException as e:
            return URLHausResult(
                service='URLHaus',
                status='error',
                timestamp=datetime.now().isoformat(),
                url="https://urlhaus.abuse.ch/",
                error=f"Request failed: {str(e)}"
            )
        except json.JSONDecodeError as e:
            return URLHausResult(
                service='URLHaus',
                status='error',
                timestamp=datetime.now().isoformat(),
                url="https://urlhaus.abuse.ch/",
                error=f"Invalid JSON response: {str(e)}"
            )

    def _virustotal_url(self, url: str) -> VirusTotalResult:
        """Query VirusTotal for URL analysis"""
        self._rate_limit('virustotal')
        
        if 'virustotal' not in self.config:
            return VirusTotalResult(
                service='VirusTotal',
                status='no_api_key',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode()}",
                error="API key not provided"
            )
        
        # First, try to get existing scan
        scan_url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {
            'apikey': self.config['virustotal'],
            'resource': url
        }
        
        try:
            response = self.session.get(scan_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('response_code') == 1:
                # URL found in database
                return VirusTotalResult(
                    service='VirusTotal',
                    status='found',
                    timestamp=datetime.now().isoformat(),
                    url=data.get('permalink'),
                    detections=data.get('positives', 0),
                    total_engines=data.get('total', 0),
                    scan_date=data.get('scan_date'),
                    positives=[engine for engine, result in data.get('scans', {}).items() 
                             if result.get('detected', False)] if data.get('positives', 0) > 0 else []
                )
            else:
                # URL not found, submit for scanning
                submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
                submit_data = {
                    'apikey': self.config['virustotal'],
                    'url': url
                }
                
                submit_response = self.session.post(submit_url, data=submit_data, timeout=10)
                submit_response.raise_for_status()
                submit_result = submit_response.json()
                
                return VirusTotalResult(
                    service='VirusTotal',
                    status='submitted',
                    timestamp=datetime.now().isoformat(),
                    url=submit_result.get('permalink'),
                    error="URL submitted for analysis. Check back later for results."
                )
                
        except requests.exceptions.RequestException as e:
            return VirusTotalResult(
                service='VirusTotal',
                status='error',
                timestamp=datetime.now().isoformat(),
                url=f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode()}",
                error=str(e)
            )
    
    def analyze(self, input_value: str, input_type: str = None) -> Dict:
        """
        Main analysis method that routes to appropriate analyzer
        
        Args:
            input_value: The value to analyze (IP, domain, hash, or URL)
            input_type: Optional type specification ('ip', 'domain', 'hash', 'url', or None for auto-detect)
            
        Returns:
            Dictionary containing analysis results
        """
        if input_type is None:
            input_type = self._detect_input_type(input_value)
        
        if input_type == 'unknown':
            return {
                'error': 'Unable to determine input type',
                'input_value': input_value,
                'detected_type': input_type
            }
        
        analysis_result = {
            'input_value': input_value,
            'input_type': input_type,
            'analysis_timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        try:
            if input_type == 'hash':
                analysis_result['results'] = self.analyze_hash(input_value)
            elif input_type == 'ip':
                analysis_result['results'] = self.analyze_ip(input_value)
            elif input_type == 'domain':
                analysis_result['results'] = self.analyze_domain(input_value)
            elif input_type == 'url':
                analysis_result['results'] = self.analyze_url(input_value)
        except Exception as e:
            analysis_result['error'] = str(e)
        
        return analysis_result

def load_config(config_file: str = None) -> Dict[str, str]:
    """Load configuration from file"""
    import os
    
    config = {}
    
    # Try to load from file
    if config_file:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_file} not found")
        except json.JSONDecodeError:
            print(f"Invalid JSON in config file {config_file}")
    return config

def print_results(results: Dict):
    """Pretty print analysis results"""
    print("\n" + "="*80)
    print(f"OSINT ANALYSIS RESULTS")
    print("="*80)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print(f"📋 Input: {results['input_value']}")
    print(f"🏷️  Type: {results['input_type'].upper()}")
    print(f"⏰ Timestamp: {results['analysis_timestamp']}")
    print("\n" + "-"*80)
    
    for service_name, result in results.get('results', {}).items():
        if hasattr(result, 'service'):
            print(f"\n🔍 {result.service}")
            print(f"   Status: {result.status}")
            
            if result.error:
                print(f"   ❌ Error: {result.error}")
                continue
            
            # Print service-specific information
            result_dict = asdict(result)
            for key, value in result_dict.items():
                if key not in ['service', 'status', 'timestamp', 'error', 'url'] and value is not None:
                    if isinstance(value, list):
                        if value:
                            # Special handling for URLHaus payloads
                            if key == 'payloads' and service_name == 'urlhaus':
                                print(f"   Payloads ({len(value)}):")
                                for i, payload in enumerate(value, 1):
                                    print(f"     {i}. SHA256: {payload.get('sha256', 'N/A')}")
                                    print(f"        File Type: {payload.get('file_type', 'N/A')}")
                                    print(f"        File Size: {payload.get('file_size', 'N/A')} bytes")
                                    print(f"        First Seen: {payload.get('first_seen', 'N/A')}")
                            else:
                                print(f"   {key.replace('_', ' ').title()}: {', '.join(map(str, value))}")
                    else:
                        print(f"   {key.replace('_', ' ').title()}: {value}")
            
            if result.url:
                print(f"   🔗 Report: {result.url}")
        
        print("-" * 40)


def convert_nested_dataclasses(obj):
    """Recursively convert dataclasses inside a nested dictionary."""
    if isinstance(obj, dict):
        return {k: convert_nested_dataclasses(v) for k, v in obj.items()}
    elif hasattr(obj, '__dataclass_fields__'):
        return convert_nested_dataclasses(asdict(obj))
    elif isinstance(obj, list):
        return [convert_nested_dataclasses(v) for v in obj]
    else:
        return obj

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='OSINT Analysis Tool')
    parser.add_argument('input', nargs='?', help='IP, domain, hash, or URL to analyze (optional if using --input-file)')
    parser.add_argument('-t', '--type', choices=['ip', 'domain', 'hash', 'url'], 
                        help='Specify input type (auto-detect if not provided)')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-o', '--output', help='Output JSON file for results', default='analysis_results.json')
    parser.add_argument('--input-file', help='Path to a text file containing IOCs to analyze (one per line)')
    parser.add_argument('--json', action='store_true', help='Print results as JSON')

    args = parser.parse_args()

    if not args.input and not args.input_file:
        parser.error("You must provide either a single input or an input file (--input-file).")

    # Load configuration
    config = load_config(args.config)

    if not config:
        print("⚠️  Warning: No API keys configured. Limited functionality available.")
        print("   Set API keys via config file.")

    # Initialize analyzer
    analyzer = OSINTAnalyzer(config)

    # Collect all results
    all_results = []

    # Analyze single input
    if args.input:
        print(f"🚀 Starting analysis of: {args.input}")
        result = analyzer.analyze(args.input, args.type)
        all_results.append(result)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_results(result)

    # Analyze from file
    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                iocs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Input file '{args.input_file}' not found.")
            sys.exit(1)

        print(f"\n📂 Loaded {len(iocs)} IOCs from file: {args.input_file}")
        for ioc in iocs:
            print(f"\n🔎 Analyzing: {ioc}")
            result = analyzer.analyze(ioc)
            all_results.append(result)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print_results(result)

    # Convert to JSON-safe format
    serializable_results = [convert_nested_dataclasses(r) for r in all_results]

    # Generate metadata summary
    summary = {
        "ioc_count": len(serializable_results),
        "timestamp": datetime.now().isoformat(),
        "types_analyzed": list({r['input_type'] for r in serializable_results}),
        "verdicts": {
            "found": sum(
                1 for r in serializable_results
                for result in r.get("results", {}).values()
                if result.get("status") == "found"
            ),
            "not_found": sum(
                1 for r in serializable_results
                for result in r.get("results", {}).values()
                if result.get("status") == "not_found"
            ),
            "errors": sum(
                1 for r in serializable_results
                for result in r.get("results", {}).values()
                if result.get("status") == "error"
            ),
        }
    }

    # Final JSON structure
    output_data = {
        "metadata": summary,
        "results": serializable_results
    }

    # Save to file
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n💾 All results saved to: {args.output}")


if __name__ == "__main__":
    main()
