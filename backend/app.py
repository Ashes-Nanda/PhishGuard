from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import requests
import re
import tldextract
from urllib.parse import urlparse
import os
from typing import List, Dict
import time
from datetime import datetime, timedelta
from collections import deque
from dotenv import load_dotenv
from ml_model import URLFeatureExtractor
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor
import asyncpg

load_dotenv()  # Add this line at the top after imports

app = FastAPI()
url_feature_extractor = URLFeatureExtractor()

class URLCheckRequest(BaseModel):
    url: str

# Add new classes for threat categorization
class ThreatSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory:
    PHISHING = "phishing"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"
    UNWANTED = "unwanted"
    MALICIOUS = "malicious"

class ThreatInfo:
    def __init__(self, message: str, category: str, severity: str):
        self.message = message
        self.category = category
        self.severity = severity

class URLCheckResponse(BaseModel):
    isSafe: bool
    threats: List[str]
    message: str
    severity: str
    categories: List[str]
    detectionCount: dict

# Add cache implementation
class URLScanCache:
    def __init__(self, ttl_seconds: int = 3600):  # 1 hour cache by default
        self.cache: Dict[str, dict] = {}
        self.ttl_seconds = ttl_seconds

    def get(self, url: str) -> dict | None:
        if url in self.cache:
            cache_entry = self.cache[url]
            if datetime.now().timestamp() - cache_entry['timestamp'] < self.ttl_seconds:
                return cache_entry['data']
            else:
                # Remove expired entry
                del self.cache[url]
        return None

    def set(self, url: str, data: dict):
        self.cache[url] = {
            'data': data,
            'timestamp': datetime.now().timestamp()
        }

    def cleanup(self):
        current_time = datetime.now().timestamp()
        expired_keys = [
            url for url, entry in self.cache.items()
            if current_time - entry['timestamp'] > self.ttl_seconds
        ]
        for url in expired_keys:
            del self.cache[url]

# Initialize cache
url_cache = URLScanCache()

class PhishingDetector:
    def __init__(self):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not self.virustotal_api_key:
            print("Warning: VirusTotal API key not found in environment variables")
        else:
            print("VirusTotal API key loaded successfully")

    def get_cached_result(self, url: str) -> dict | None:
        return url_cache.get(url)

    def store_result(self, url: str, result: dict):
        url_cache.set(url, result)

    def check_virustotal(self, url: str) -> dict:
        if not self.virustotal_api_key:
            print("VirusTotal API key not found")
            return {"error": "VirusTotal API key not configured"}
        
        # Using VirusTotal API v3
        base_url = "https://www.virustotal.com/api/v3"
        headers = {
            "x-apikey": self.virustotal_api_key.strip(),
            "Accept": "application/json"
        }

        try:
            print(f"Scanning URL: {url}")
            
            # First, try to get existing analysis
            url_id = hashlib.sha256(url.encode()).hexdigest()
            print(f"URL ID: {url_id}")
            
            try:
                existing_url = f"{base_url}/urls/{url_id}"
                print("Checking for existing analysis...")
                existing_response = requests.get(existing_url, headers=headers)
                
                if existing_response.ok:
                    existing_data = existing_response.json()
                    last_analysis = existing_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    if last_analysis:
                        print("Found existing analysis")
                        return {
                            "positives": last_analysis.get('malicious', 0),
                            "total": sum(last_analysis.values()),
                            "scan_date": existing_data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                            "results": existing_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                        }
            except Exception as e:
                print(f"Error checking existing analysis: {str(e)}")
            
            # If no existing analysis or error, submit new scan
            print("Submitting URL to VirusTotal...")
            scan_url = f"{base_url}/urls"
            scan_data = {"url": url}
            scan_response = requests.post(scan_url, headers=headers, data=scan_data)
            
            if not scan_response.ok:
                print(f"VirusTotal scan submission failed: {scan_response.status_code} - {scan_response.text}")
                return {"error": f"VirusTotal scan submission failed: {scan_response.status_code}"}
                
            result = scan_response.json()
            print("URL submission successful")
            
            # Get the analysis ID
            analysis_id = result.get("data", {}).get("id")
            if not analysis_id:
                print("Failed to get analysis ID from response")
                return {"error": "Failed to get analysis ID"}

            print(f"Got analysis ID: {analysis_id}")
            
            # Step 2: Get analysis results with increased retries and better queued handling
            max_attempts = 10  # Increased from 3 to 10 attempts
            attempts = 0
            while attempts < max_attempts:
                analysis_url = f"{base_url}/analyses/{analysis_id}"
                print(f"Fetching analysis results (attempt {attempts + 1}/{max_attempts})...")
                analysis_response = requests.get(analysis_url, headers=headers)
                
                if not analysis_response.ok:
                    print(f"Analysis fetch failed: {analysis_response.status_code} - {analysis_response.text}")
                    return {"error": f"Analysis fetch failed: {analysis_response.status_code}"}
                    
                analysis_result = analysis_response.json()
                status = analysis_result.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    stats = analysis_result.get("data", {}).get("attributes", {}).get("stats", {})
                    results = {
                        "positives": stats.get("malicious", 0),
                        "total": sum(stats.values()),
                        "scan_date": analysis_result.get("data", {}).get("attributes", {}).get("date"),
                        "results": analysis_result.get("data", {}).get("attributes", {}).get("results", {})
                    }
                    print(f"Analysis complete: {results}")
                    return results
                elif status == "queued":
                    print("Analysis is queued, waiting longer...")
                    time.sleep(6)  # Increased delay for queued status
                else:
                    print(f"Analysis status: {status}, waiting...")
                    time.sleep(3)

                attempts += 1

            print("Analysis timed out after max attempts")
            # Return partial results if available
            if analysis_result and "data" in analysis_result:
                stats = analysis_result.get("data", {}).get("attributes", {}).get("stats", {})
                return {
                    "positives": stats.get("malicious", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "scan_date": analysis_result.get("data", {}).get("attributes", {}).get("date"),
                    "results": analysis_result.get("data", {}).get("attributes", {}).get("results", {}),
                    "status": "timeout",
                    "partial_results": True
                }
            return {"error": "Analysis timeout"}

        except requests.exceptions.RequestException as e:
            print(f"VirusTotal API error: {str(e)}")
            return {"error": f"VirusTotal API error: {str(e)}"}

    def calculate_severity(self, vt_positives: int, total_threats: int) -> str:
        if vt_positives >= 10:
            return ThreatSeverity.CRITICAL
        elif vt_positives >= 5:
            return ThreatSeverity.HIGH
        elif vt_positives >= 2:
            return ThreatSeverity.MEDIUM
        elif total_threats > 0:
            return ThreatSeverity.LOW
        return ThreatSeverity.LOW

    def get_severity_message(self, severity: str) -> str:
        messages = {
            ThreatSeverity.CRITICAL: "CRITICAL THREAT DETECTED! DO NOT PROCEED - This URL is confirmed malicious by multiple security vendors.",
            ThreatSeverity.HIGH: "HIGH RISK! This URL shows strong indicators of being malicious.",
            ThreatSeverity.MEDIUM: "CAUTION! This URL has been flagged as potentially dangerous.",
            ThreatSeverity.LOW: "Exercise caution with this URL.",
        }
        return messages.get(severity, "Unknown threat level")

    def process_virustotal_results(self, vt_results: dict) -> tuple[List[str], Dict, List[str]]:
        threats = []
        categories = set()
        detection_count = {
            "phishing": 0,
            "malware": 0,
            "suspicious": 0,
            "malicious": 0
        }
        
        if "error" in vt_results:
            threats.append(f"VirusTotal scan error: {vt_results['error']}")
            return threats, detection_count, list(categories)

        positives = vt_results.get("positives", 0)
        total = vt_results.get("total", 0)
        
        if positives > 0:
            threats.append(f"VirusTotal: {positives}/{total} security vendors flagged this URL")
            
            results = vt_results.get("results", {})
            for engine, result in results.items():
                category = result.get("category", "").lower()
                result_type = result.get("result", "suspicious").lower()
                
                if category == "malicious":
                    if "phish" in result_type:
                        detection_count["phishing"] += 1
                        categories.add(ThreatCategory.PHISHING)
                    elif "malware" in result_type:
                        detection_count["malware"] += 1
                        categories.add(ThreatCategory.MALWARE)
                    else:
                        detection_count["malicious"] += 1
                        categories.add(ThreatCategory.MALICIOUS)
                    
                    threats.append(f"- {engine}: {result_type}")

        return threats, detection_count, list(categories)

    def check_suspicious_patterns(self, url: str) -> List[str]:
        threats = []
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        
        # Known legitimate domains (whitelist)
        legitimate_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
            'facebook.com', 'github.com', 'linkedin.com', 'twitter.com'
        }
        
        if domain_info.domain + '.' + domain_info.suffix in legitimate_domains:
            return []

        # Enhanced suspicious URL patterns
        suspicious_patterns = [
            # Brand impersonation patterns
            (r"paypal.*[^.]\.(?!com\b)", "Suspicious PayPal domain - possible phishing"),
            (r"google.*[^.]\.(?!com\b)", "Suspicious Google domain - possible phishing"),
            (r"microsoft.*[^.]\.(?!com\b)", "Suspicious Microsoft domain - possible phishing"),
            (r"apple.*[^.]\.(?!com\b)", "Suspicious Apple domain - possible phishing"),
            (r"amazon.*[^.]\.(?!com\b)", "Suspicious Amazon domain - possible phishing"),
            (r"facebook.*[^.]\.(?!com\b)", "Suspicious Facebook domain - possible phishing"),
            
            # Authentication and security related patterns
            (r"(login|signin|verify|secure|account|auth|password|pwd|user|admin)\d*-?", 
             "Contains authentication-related terms - exercise caution"),
            (r"(banking|payment|wallet|crypto|bitcoin|verify|confirm)", 
             "Contains financial or verification terms - exercise caution"),
            
            # Technical patterns
            (r"\.php\?.*=", "Contains suspicious PHP parameters"),
            (r"[0-9]{10,}", "Contains unusually long numbers"),
            (r"[a-zA-Z0-9]{25,}", "Contains suspicious long strings"),
            (r"[a-zA-Z0-9+/]{30,}={0,2}", "Contains possible encoded/encrypted data"),
            
            # URL manipulation patterns
            (r"[<>{}\\|^~`'\"]", "Contains suspicious special characters"),
            (r"(\.{2,}|//+)", "Contains suspicious path manipulation"),
            (r"@", "Contains @ symbol - possible URL manipulation"),
            
            # Subdomain abuse
            (r"([a-zA-Z0-9-]+\.){3,}", "Contains excessive subdomains"),
            
            # Mixed character sets (homograph attacks)
            (r"[а-яА-Я].*[a-zA-Z]|[a-zA-Z].*[а-яА-Я]", "Contains mixed alphabet characters - possible homograph attack")
        ]

        # Check all patterns
        for pattern, message in suspicious_patterns:
            if re.search(pattern, url.lower()):
                threats.append(message)

        # Check for IP address instead of domain
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        if re.match(ip_pattern, domain_info.domain) or re.search(ip_pattern, url):
            threats.append("URL uses IP address instead of domain name - highly suspicious")

        # Enhanced TLD checking
        suspicious_tlds = [
            ".xyz", ".top", ".work", ".loan", ".click", ".tk", ".ml", ".ga", ".cf", 
            ".gq", ".buzz", ".country", ".kim", ".cn", ".bid", ".download", ".xin", 
            ".gdn", ".racing", ".jetzt", ".win", ".vip"
        ]
        
        if any(domain_info.suffix.endswith(tld) for tld in suspicious_tlds):
            threats.append(f"URL uses suspicious top-level domain (.{domain_info.suffix})")

        # Check domain age if possible
        try:
            import whois
            domain = domain_info.domain + '.' + domain_info.suffix
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:
                    threats.append(f"Domain is very new (created {domain_age} days ago)")
        except:
            pass

        # Check URL length
        if len(url) > 100:
            threats.append("URL is unusually long")

        return threats

# Rate limiting setup
class RateLimiter:
    def __init__(self, requests_per_minute=4):  # VirusTotal public API limit is 4 requests per minute
        self.requests_per_minute = requests_per_minute
        self.requests = deque()

    async def check_rate_limit(self):
        now = datetime.now()
        
        # Remove requests older than 1 minute
        while self.requests and (now - self.requests[0]) > timedelta(minutes=1):
            self.requests.popleft()

        if len(self.requests) >= self.requests_per_minute:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please wait before making another request."
            )

        self.requests.append(now)

rate_limiter = RateLimiter()

def normalize_confidence_scores(vt_results: dict, ml_results: dict, suspicious_patterns_count: int = 0) -> dict:
    """Normalize and combine confidence scores from VirusTotal and ML model."""
    try:
        # Calculate VirusTotal confidence
        total_scanners = vt_results.get('total', 0)
        if total_scanners == 0:
            vt_confidence = 0.5  # Neutral score when no VT data
        else:
            harmless = vt_results.get('stats', {}).get('harmless', 0)
            malicious = vt_results.get('stats', {}).get('malicious', 0)
            suspicious = vt_results.get('stats', {}).get('suspicious', 0)
            
            # Weight the results more conservatively
            vt_confidence = (harmless / total_scanners)
            threat_confidence = ((malicious * 1.0 + suspicious * 0.7) / total_scanners)
            
            # Invert threat confidence to match our safe/unsafe scale
            vt_confidence = max(0.0, min(1.0, 1.0 - threat_confidence))

        # Get ML confidence and adjust based on features
        ml_confidence = float(ml_results.get('confidence', 0.0))
        
        # Adjust confidence based on suspicious patterns - more aggressive penalties
        base_pattern_penalty = 0.15  # Base penalty per pattern
        pattern_penalty = min(base_pattern_penalty * suspicious_patterns_count, 0.8)  # Cap at 80%
        
        # Additional penalty for certain high-risk features
        if ml_results.get('features', {}).get('has_ip_address'):
            pattern_penalty += 0.2
        if ml_results.get('features', {}).get('has_at_symbol'):
            pattern_penalty += 0.15
        if ml_results.get('features', {}).get('has_multiple_subdomains'):
            pattern_penalty += 0.1
            
        # Combine scores with adjusted weights (40% VT, 30% ML, 30% patterns)
        combined_confidence = (vt_confidence * 0.4) + (ml_confidence * 0.3) - pattern_penalty
        
        # Ensure the final score is between 0 and 1
        combined_confidence = max(0.0, min(1.0, combined_confidence))
        
        # More conservative threshold for safety
        is_safe = combined_confidence >= 0.85  # Increased from 0.8
        
        # If any critical patterns are found, override safety
        if suspicious_patterns_count >= 3 or pattern_penalty >= 0.5:
            is_safe = False
            
        return {
            "is_safe": is_safe,
            "confidence": combined_confidence,
            "vt_confidence": vt_confidence,
            "ml_confidence": ml_confidence,
            "pattern_penalty": pattern_penalty
        }
    except Exception as e:
        print(f"Error normalizing confidence scores: {str(e)}")
        return {
            "is_safe": False,
            "confidence": 0.0,
            "vt_confidence": 0.0,
            "ml_confidence": 0.0,
            "pattern_penalty": 0.0
        }

class CyberCellReport(BaseModel):
    url: str
    threat_type: str
    evidence: dict
    reporter_info: dict = None  # Optional reporter information

@app.post("/api/report-to-cybercell")
async def report_to_cybercell(report: CyberCellReport):
    try:
        # Format the report for MP Cyber Cell
        cyber_cell_report = {
            "report_type": "PHISHING_URL",
            "threat_details": {
                "url": report.url,
                "threat_type": report.threat_type,
                "detection_evidence": report.evidence,
                "timestamp": datetime.now().isoformat(),
                "source": "URLGuardian",
                "reporter_info": report.reporter_info
            }
        }

        # Store report in local database
        # TODO: Implement secure database storage
        
        # In production, this would be the actual MP Cyber Cell API endpoint
        # For hackathon, simulate the API call
        return {
            "success": True,
            "message": "Report successfully submitted to MP Cyber Cell",
            "reference_id": hashlib.md5(f"{report.url}-{datetime.now().isoformat()}".encode()).hexdigest()
        }
    except Exception as e:
        print(f"Error submitting cyber cell report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit report to Cyber Cell")

class AnonymousTip(BaseModel):
    tip_type: str  # URL, SMS, EMAIL, OTHER
    content: str
    additional_details: str = None
    evidence_urls: List[str] = []

@app.post("/api/submit-anonymous-tip")
async def submit_anonymous_tip(tip: AnonymousTip):
    try:
        # Format the anonymous tip
        tip_data = {
            "type": tip.tip_type,
            "content": tip.content,
            "details": tip.additional_details,
            "evidence": tip.evidence_urls,
            "timestamp": datetime.now().isoformat(),
            "source": "URLGuardian Anonymous Tip"
        }

        # Store tip securely
        # TODO: Implement secure database storage
        
        return {
            "success": True,
            "message": "Anonymous tip submitted successfully",
            "tip_id": hashlib.md5(f"{tip.content}-{datetime.now().isoformat()}".encode()).hexdigest()
        }
    except Exception as e:
        print(f"Error submitting anonymous tip: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit anonymous tip")

# Government Database Integration
async def check_government_databases(url: str) -> dict:
    try:
        # Simulate checking multiple government databases
        # In production, these would be real API calls to government cybercrime databases
        databases_checked = {
            "mp_police_db": True,
            "cert_in_db": True,
            "interpol_db": True
        }
        
        # Simulate findings
        return {
            "found_in_databases": False,  # Would be True if found in any database
            "databases_checked": databases_checked,
            "last_checked": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error checking government databases: {str(e)}")
        return {
            "error": "Failed to check government databases",
            "databases_checked": {}
        }

@app.post("/api/scan-url")
async def scan_url(request: URLCheckRequest):
    try:
        detector = PhishingDetector()
        url = request.url
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Create tasks for parallel execution
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            # Run quick checks immediately
            pattern_threats = await loop.run_in_executor(executor, detector.check_suspicious_patterns, url)
            ml_prediction = await loop.run_in_executor(executor, url_feature_extractor.predict_url, url)

            # Return initial results quickly
            initial_confidence = normalize_confidence_scores(
                {},  # No VT results yet
                ml_prediction,
                len(pattern_threats) if pattern_threats else 0
            )

            initial_result = {
                "isSafe": initial_confidence["is_safe"],
                "threats": pattern_threats,
                "message": "Initial analysis complete, full scan in progress...",
                "severity": "medium" if pattern_threats else "low",
                "categories": ["suspicious"] if pattern_threats else [],
                "detectionCount": {
                    "phishing": 1 if ml_prediction.get("is_phishing") else 0,
                    "malware": 0,
                    "suspicious": len(pattern_threats) if pattern_threats else 0,
                    "malicious": 0
                },
                "confidence": initial_confidence["confidence"],
                "mlConfidence": initial_confidence["ml_confidence"],
                "vtConfidence": 0.5,  # Neutral score until VT results
                "whitelisted": ml_prediction.get("whitelisted", False),
                "isPartialResult": True
            }

            # Store initial scan result in database
            async with app.state.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO scan_history (url, is_safe, threats, confidence, severity, message)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, 
                url, 
                initial_result["isSafe"],
                initial_result["threats"],
                initial_result["confidence"],
                initial_result["severity"],
                initial_result["message"]
                )

            # Start VirusTotal scan in background
            vt_task = loop.run_in_executor(executor, detector.check_virustotal, url)

            # Return initial results immediately
            yield initial_result

            # Wait for VirusTotal results with timeout
            try:
                vt_results = await asyncio.wait_for(vt_task, timeout=30)  # 30 second timeout
            except asyncio.TimeoutError:
                vt_results = {"error": "VirusTotal scan timeout"}

            # Final confidence calculation with all results
            confidence_scores = normalize_confidence_scores(
                vt_results if "error" not in vt_results else {},
                ml_prediction,
                len(pattern_threats) if pattern_threats else 0
            )

            # Process all threats and categories
            threats = pattern_threats.copy() if pattern_threats else []
            categories = set(["suspicious"]) if pattern_threats else set()
            detection_count = {
                "phishing": 0,
                "malware": 0,
                "suspicious": len(pattern_threats) if pattern_threats else 0,
                "malicious": 0
            }

            if ml_prediction.get("is_phishing"):
                threats.append(f"ML Model: Detected as potential phishing website (Confidence: {ml_prediction['confidence']:.2%})")
                categories.add("phishing")
                detection_count["phishing"] += 1

            # Update scan result in database with final results
            async with app.state.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE scan_history 
                    SET is_safe = $1, threats = $2, confidence = $3, severity = $4, message = $5
                    WHERE url = $6 AND timestamp = (
                        SELECT MAX(timestamp) FROM scan_history WHERE url = $6
                    )
                """,
                confidence_scores["is_safe"],
                threats,
                confidence_scores["confidence"],
                "high" if not confidence_scores["is_safe"] else "low",
                "URL appears to be malicious" if not confidence_scores["is_safe"] else "URL appears to be safe",
                url
                )

            return {
                "isSafe": confidence_scores["is_safe"],
                "threats": threats,
                "categories": list(categories),
                "detectionCount": detection_count,
                "confidence": confidence_scores["confidence"],
                "mlConfidence": confidence_scores["ml_confidence"],
                "vtConfidence": confidence_scores["vt_confidence"],
                "message": "URL appears to be malicious" if not confidence_scores["is_safe"] else "URL appears to be safe",
                "severity": "high" if not confidence_scores["is_safe"] else "low",
                "whitelisted": ml_prediction.get("whitelisted", False),
                "timestamp": datetime.now().isoformat()
            }

    except Exception as e:
        print(f"Error scanning URL: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to scan URL: {str(e)}"
        )

# Add cache cleanup endpoint
@app.post("/api/cache/cleanup")
async def cleanup_cache():
    url_cache.cleanup()
    return {"message": "Cache cleanup completed"}

# Add cache stats endpoint
@app.get("/api/cache/stats")
async def cache_stats():
    return {
        "cached_urls": len(url_cache.cache),
        "cache_size_mb": sum(len(str(v)) for v in url_cache.cache.values()) / 1024 / 1024
    }

@app.get("/api/known-phishing-urls")
async def get_known_phishing_urls():
    try:
        # Initialize the phishing detector
        detector = PhishingDetector()
        
        # Get URLs from our local database that have been marked as unsafe
        unsafe_urls = []
        
        # Query the database for URLs marked as unsafe
        # This is a simplified version - you may want to add pagination for large datasets
        query = "SELECT url FROM scan_history WHERE is_safe = false ORDER BY timestamp DESC LIMIT 1000"
        async with app.state.pool.acquire() as conn:
            rows = await conn.fetch(query)
            unsafe_urls = [row['url'] for row in rows]
        
        return {"urls": unsafe_urls}
    except Exception as e:
        print(f"Error fetching known phishing URLs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch known phishing URLs"
        )

# Database initialization
async def init_db():
    try:
        async with app.state.pool.acquire() as conn:
            # Create scan_history table if it doesn't exist
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id SERIAL PRIMARY KEY,
                    url TEXT NOT NULL,
                    is_safe BOOLEAN NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    threats TEXT[],
                    confidence FLOAT,
                    severity TEXT,
                    message TEXT
                )
            """)
    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        raise e

@app.on_event("startup")
async def startup():
    try:
        # Create the database pool
        app.state.pool = await asyncpg.create_pool(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            host=os.getenv('DB_HOST')
        )
        
        # Initialize the database
        await init_db()
    except Exception as e:
        print(f"Startup error: {str(e)}")
        raise e

@app.on_event("shutdown")
async def shutdown():
    if hasattr(app.state, "pool"):
        await app.state.pool.close() 