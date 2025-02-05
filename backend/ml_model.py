import joblib
import numpy as np
import re
import whois
from datetime import datetime
import socket
import requests
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
import os

class URLFeatureExtractor:
    def __init__(self):
        # Load the trained model
        model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
        self.model = joblib.load(model_path)
        # Whitelist of known legitimate domains
        self.whitelist = {
            'google.com', 'www.google.com',
            'microsoft.com', 'www.microsoft.com',
            'apple.com', 'www.apple.com',
            'amazon.com', 'www.amazon.com',
            'facebook.com', 'www.facebook.com',
            'twitter.com', 'www.twitter.com',
            'linkedin.com', 'www.linkedin.com',
            'github.com', 'www.github.com'
        }

    def have_ip_address(self, url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
        return -1 if match else 1

    def url_length(self, url):
        if len(url) < 54:
            return 1
        elif 54 <= len(url) <= 75:
            return 0
        else:
            return -1

    def url_shortener(self, url):
        match = re.search('bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
                         'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
                         'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
                         'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
                         'db\\.tt|qr\\.ae|adf\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
                         'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|'
                         'x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|tr\\.im|link\\.zip\\.net', url)
        return -1 if match else 1

    def have_atrate_symbol(self, url):
        return -1 if '@' in url else 1

    def double_slash_redirect(self, url):
        list = [x.start(0) for x in re.finditer('\\.', url)]
        return -1 if list[len(list)-1] > 6 else 1

    def prefix_suffix(self, url):
        return -1 if '-' in url else 1

    def have_subdomain(self, url):
        if self.have_ip_address(url) == -1:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
            pos = match.end(0)
            url = url[pos:]
        list = [x.start(0) for x in re.finditer('\\.', url)]
        if len(list) <= 3:
            return 1
        elif len(list) == 4:
            return 0
        else:
            return -1

    def domain_registration_length(self, domain):
        try:
            expiry_date = domain.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            exp = datetime.strftime(expiry_date, "%Y-%m-%d")
            expires = datetime.strptime(exp, "%Y-%m-%d")
            today = datetime.today()
            tp = datetime.strftime(today, "%Y-%m-%d")
            today_date = datetime.strptime(tp, "%Y-%m-%d")
            registration_length = abs((expires - today_date).days)
            return -1 if registration_length / 365 <= 1 else 1
        except:
            return -1

    def https_token(self, url):
        match = re.finditer('https:// | http:// | http | https', url)
        return -1 if len(list(match)) != 1 else 1

    def extract_features(self, url):
        """Extract features from URL for phishing detection."""
        features = np.zeros(31)  # Initialize array with zeros for all features
        
        # Basic URL features
        features[0] = self.have_ip_address(url)
        features[1] = self.url_length(url)
        features[2] = self.url_shortener(url)
        features[3] = self.have_atrate_symbol(url)
        features[4] = self.double_slash_redirect(url)
        features[5] = self.prefix_suffix(url)
        features[6] = self.have_subdomain(url)
        
        # All other features default to 0 (equivalent to 'normal' behavior)
        # This simplifies our feature extraction while maintaining the expected feature count
        
        return features

    def predict_url(self, url):
        """Predict if a URL is phishing."""
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check whitelist first
            if domain in self.whitelist or parsed.netloc in self.whitelist:
                return {
                    "is_phishing": False,
                    "confidence": 1.0,
                    "features": {},
                    "whitelisted": True
                }

            features = self.extract_features(url)
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0]
            
            # Get confidence score - ensure it's between 0 and 1
            confidence = max(0.0, min(1.0, float(probability[1] if prediction == 1 else probability[0])))
            
            # Extract active features for explanation
            active_features = {
                "has_ip_address": features[0] == -1,
                "long_url": features[1] == -1,
                "uses_shortener": features[2] == -1,
                "has_at_symbol": features[3] == -1,
                "has_double_slash": features[4] == -1,
                "has_prefix_suffix": features[5] == -1,
                "has_multiple_subdomains": features[6] == -1
            }
            
            return {
                "is_phishing": prediction == -1,
                "confidence": confidence,
                "features": active_features,
                "whitelisted": False
            }
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "features": {},
                "whitelisted": False
            } 