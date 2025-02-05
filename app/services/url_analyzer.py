import re
from typing import Dict, Any, List, Tuple
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import numpy as np
from datetime import datetime
import tld
import socket
import whois
from concurrent.futures import ThreadPoolExecutor
import ssl
import dns.resolver
import urllib3

# Disable SSL warnings for the session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class URLAnalyzer:
    def __init__(self):
        # Common phishing keywords
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'verification', 'account',
            'password', 'secure', 'banking', 'update', 'confirm',
            'paypal', 'security', 'microsoft', 'apple', 'google',
            'recover', 'unlock', 'authenticate', 'wallet', 'suspended'
        ]
        
        # Common legitimate domains
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'github.com', 'linkedin.com', 'twitter.com',
            'instagram.com', 'paypal.com', 'chase.com', 'wellsfargo.com'
        }
        
        # Brand names to check for spoofing
        self.brand_names = [
            'paypal', 'microsoft', 'apple', 'google', 'facebook',
            'amazon', 'netflix', 'linkedin', 'instagram', 'twitter'
        ]

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential phishing indicators using multiple methods
        """
        features = {}
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Basic URL analysis
        features.update(self._analyze_url_structure(url, parsed_url))
        
        # Domain analysis
        features.update(self._analyze_domain(domain))
        
        # SSL/TLS analysis
        features.update(self._analyze_ssl(domain))
        
        # Content analysis
        features.update(await self._analyze_content(url))
        
        # Calculate final risk score
        risk_score = self._calculate_risk_score(features)
        
        return {
            'url': url,
            'is_phishing': risk_score > 0.5,
            'confidence_score': 1 - risk_score,
            'risk_score': risk_score,
            'analysis_features': features,
            'timestamp': datetime.utcnow(),
        }

    def _analyze_url_structure(self, url: str, parsed_url) -> Dict[str, Any]:
        """
        Analyze URL structure for suspicious patterns
        """
        features = {}
        
        # Basic metrics
        features['length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_at'] = url.count('@')
        features['num_percent'] = url.count('%')
        features['num_queries'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        features['num_fragments'] = len(parsed_url.fragment.split('&')) if parsed_url.fragment else 0
        features['has_port'] = bool(parsed_url.port)
        
        # URL complexity
        features['path_length'] = len(parsed_url.path)
        features['path_depth'] = len([x for x in parsed_url.path.split('/') if x])
        
        # Suspicious patterns
        features['has_suspicious_keywords'] = any(keyword in url.lower() for keyword in self.suspicious_keywords)
        features['has_hex_chars'] = bool(re.search(r'%[0-9a-fA-F]{2}', url))
        features['has_ip_address'] = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))
        
        return features

    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain characteristics
        """
        features = {}
        
        try:
            # Domain age and registration info
            w = whois.whois(domain)
            features['domain_age'] = (datetime.now() - w.creation_date[0]).days if isinstance(w.creation_date, list) else (datetime.now() - w.creation_date).days
            features['domain_expiry'] = bool(w.expiration_date)
            features['domain_registered'] = bool(w.registrar)
        except:
            features['domain_age'] = -1
            features['domain_expiry'] = False
            features['domain_registered'] = False
        
        # DNS records
        try:
            dns.resolver.resolve(domain, 'MX')
            features['has_mx_record'] = True
        except:
            features['has_mx_record'] = False
        
        # Check for brand spoofing
        features['possible_brand_spoofing'] = any(brand in domain.lower() and not domain.endswith(f'.{brand}.com') 
                                                for brand in self.brand_names)
        
        # Legitimate domain check
        features['is_known_legitimate'] = any(domain.endswith(d) for d in self.legitimate_domains)
        
        return features

    def _analyze_ssl(self, domain: str) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate
        """
        features = {}
        
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                features['has_ssl'] = True
                features['ssl_issued_to'] = cert['subject'][0][0][1]
                features['ssl_issuer'] = cert['issuer'][0][0][1]
                features['ssl_version'] = s.version()
        except:
            features['has_ssl'] = False
            features['ssl_issued_to'] = None
            features['ssl_issuer'] = None
            features['ssl_version'] = None
        
        return features

    async def _analyze_content(self, url: str) -> Dict[str, Any]:
        """
        Analyze webpage content for phishing indicators
        """
        features = {}
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, timeout=5, verify=False, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form analysis
            forms = soup.find_all('form')
            features['has_password_field'] = bool(soup.find('input', {'type': 'password'}))
            features['num_forms'] = len(forms)
            features['form_actions_external'] = sum(1 for form in forms if form.get('action', '').startswith(('http', '//')))
            
            # Link analysis
            links = soup.find_all('a', href=True)
            external_links = [link['href'] for link in links if link['href'].startswith(('http', '//'))]
            features['num_external_links'] = len(external_links)
            features['ratio_external_links'] = len(external_links) / len(links) if links else 0
            
            # Content analysis
            text_content = soup.get_text().lower()
            features['has_urgent_text'] = any(word in text_content for word in ['urgent', 'immediate', 'suspended', 'restricted'])
            features['has_security_text'] = any(word in text_content for word in ['security', 'secure', 'protection', 'verify'])
            
            # Resource analysis
            features['num_scripts'] = len(soup.find_all('script'))
            features['num_iframes'] = len(soup.find_all('iframe'))
            
            # Meta tags
            meta_tags = soup.find_all('meta')
            features['has_favicon'] = bool(soup.find('link', rel='icon'))
            features['has_meta_description'] = bool(soup.find('meta', {'name': 'description'}))
            
        except Exception as e:
            features['fetch_error'] = str(e)
            features['has_password_field'] = False
            features['num_forms'] = 0
            features['form_actions_external'] = 0
            features['num_external_links'] = 0
            features['ratio_external_links'] = 0
            features['has_urgent_text'] = False
            features['has_security_text'] = False
            features['num_scripts'] = 0
            features['num_iframes'] = 0
            features['has_favicon'] = False
            features['has_meta_description'] = False
        
        return features

    def _calculate_risk_score(self, features: Dict[str, Any]) -> float:
        """
        Calculate the final risk score using weighted features
        """
        risk_factors = [
            # URL structure (30%)
            features['has_suspicious_keywords'] * 0.10,
            features['has_ip_address'] * 0.05,
            (features['num_dots'] > 3) * 0.05,
            features['has_hex_chars'] * 0.05,
            (features['path_depth'] > 4) * 0.05,
            
            # Domain characteristics (25%)
            (not features['domain_registered']) * 0.10,
            (features['domain_age'] < 30 if features['domain_age'] != -1 else True) * 0.05,
            (not features['has_mx_record']) * 0.05,
            features['possible_brand_spoofing'] * 0.05,
            
            # SSL/TLS (15%)
            (not features['has_ssl']) * 0.15,
            
            # Content analysis (30%)
            features['has_password_field'] * 0.10,
            (features['ratio_external_links'] > 0.6 if features['ratio_external_links'] else False) * 0.05,
            features['has_urgent_text'] * 0.05,
            (features['num_iframes'] > 0) * 0.05,
            features['form_actions_external'] * 0.05
        ]
        
        # Calculate base risk score
        risk_score = sum(risk_factors)
        
        # Reduce risk for known legitimate domains
        if features['is_known_legitimate']:
            risk_score *= 0.2
        
        # Normalize score between 0 and 1
        return min(max(risk_score, 0), 1)

# Create a singleton instance
url_analyzer = URLAnalyzer() 