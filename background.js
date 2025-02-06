class URLFeatureExtractor {
	constructor() {
		this.whitelist = new Set([
			'google.com', 'www.google.com',
			'microsoft.com', 'www.microsoft.com',
			'apple.com', 'www.apple.com',
			'amazon.com', 'www.amazon.com',
			'facebook.com', 'www.facebook.com',
			'twitter.com', 'www.twitter.com',
			'linkedin.com', 'www.linkedin.com',
			'github.com', 'www.github.com'
		]);
		
		this.weights = {
			has_ip_address: 4.0,
			long_url: 2.0,
			uses_shortener: 3.0,
			has_at_symbol: 2.5,
			has_double_slash: 2.5,
			has_prefix_suffix: 2.0,
			has_multiple_subdomains: 3.0,
			has_suspicious_keywords: 3.5,
			has_suspicious_tld: 3.5,
			has_numeric_subdomain: 3.0,
			has_random_subdomain: 3.0,
			no_ssl: 3.0,
			encoding_techniques: 3.0,
			typosquatting: 3.5,
			brand_impersonation: 4.0,
			suspicious_platform: 3.0
		};

		this.commonBrands = [
			'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 
			'facebook', 'instagram', 'twitter', 'linkedin', 'bank', 'wells',
			'chase', 'citi', 'coinbase', 'binance', 'wallet', 'crypto',
			'trezor', 'metamask', 'blockchain', 'ledger'
		];

		this.suspiciousPlatforms = [
			'webflow.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
			'glitch.me', 'repl.co', '000webhostapp.com', 'surge.sh'
		];
	}

	extractFeatures(url) {
		const features = {};
		try {
			const urlObj = new URL(url);
			const hostname = urlObj.hostname.toLowerCase();
			const path = urlObj.pathname.toLowerCase();
			const fullUrl = url.toLowerCase();

			features.has_ip_address = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.test(url);
			features.long_url = url.length > 75;
			features.uses_shortener = /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd/i.test(url);
			features.has_at_symbol = url.includes('@');
			features.has_double_slash = url.lastIndexOf('//') > 6;
			features.has_prefix_suffix = url.includes('-');
			features.has_multiple_subdomains = hostname.split('.').length > 3;
			
			const suspiciousKeywords = /login|account|secure|verify|signin|security|update|wallet|auth|confirm|password|pay|billing|crypto|recover|unlock|web3|metamask|trezor|ledger|blockchain/i;
			features.has_suspicious_keywords = suspiciousKeywords.test(hostname) || suspiciousKeywords.test(path);
			
			features.has_suspicious_tld = /.+\.(xyz|tk|ml|ga|cf|gq|pw|io|co|su|ru|bit|top|cam|monster|work|party|gdn|click|ooo|casa)$/i.test(hostname);
			features.has_numeric_subdomain = /^[0-9-]+\./.test(hostname);
			features.has_random_subdomain = /^[a-z0-9]{8,}\./.test(hostname) || /^(?!www\.)[a-z0-9]+[a-z0-9-]*[a-z0-9]+\./.test(hostname);
			features.no_ssl = !url.startsWith('https://');
			features.encoding_techniques = /%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}/.test(url);
			features.typosquatting = this.checkTyposquatting(hostname);
			features.brand_impersonation = this.checkBrandImpersonation(fullUrl);
			features.suspicious_platform = this.suspiciousPlatforms.some(platform => hostname.endsWith(platform));
		} catch (error) {
			Object.keys(this.weights).forEach(key => features[key] = true);
		}
		return features;
	}

	checkBrandImpersonation(fullUrl) {
		return this.commonBrands.some(brand => {
			if (fullUrl.includes(brand)) {
				const domainPart = new URL(fullUrl).hostname;
				return !this.whitelist.has(domainPart);
			}
			return false;
		});
	}

	checkTyposquatting(domain) {
		const commonTypos = {
			'google': /g[o0]{2}gle/i,
			'facebook': /f[a@]ceb[o0]{2}k/i,
			'microsoft': /micr[o0]s[o0]ft/i,
			'apple': /[a@]pple/i,
			'amazon': /[a@]m[a@]z[o0]n/i,
			'paypal': /p[a@]yp[a@]l/i,
			'netflix': /n[e3]tfl[i1]x/i,
			'blockchain': /bl[o0]ckch[a@][i1]n/i,
			'trezor': /tr[e3]z[o0]r/i,
			'metamask': /m[e3]t[a@]m[a@]sk/i
		};

		for (const [legitimate, pattern] of Object.entries(commonTypos)) {
			if (pattern.test(domain) && domain !== legitimate) {
				return true;
			}
		}
		return false;
	}

	predictUrl(url) {
		try {
			if (!url.startsWith('http')) {
				url = 'http://' + url;
			}

			const urlObj = new URL(url);
			const domain = urlObj.hostname.toLowerCase();
			const cleanDomain = domain.startsWith('www.') ? domain.slice(4) : domain;

			if (this.whitelist.has(cleanDomain) || this.whitelist.has(domain)) {
				return {
					is_phishing: false,
					confidence: 1.0,
					features: {},
					whitelisted: true,
					threat_level: 'safe'
				};
			}

			const features = this.extractFeatures(url);
			let weightedNegativeScore = 0;
			let totalWeight = 0;

			Object.entries(features).forEach(([feature, isNegative]) => {
				const weight = this.weights[feature];
				if (isNegative) weightedNegativeScore += weight;
				totalWeight += weight;
			});

			const confidence = totalWeight > 0 ? 
				1 - (weightedNegativeScore / totalWeight) : 0.5;

			const threat_level = confidence < 0.4 ? 'high' :
							   confidence < 0.6 ? 'medium' :
							   confidence < 0.75 ? 'low' : 'safe';

			return {
				is_phishing: confidence < 0.65,
				confidence,
				features,
				whitelisted: false,
				threat_level
			};
		} catch (error) {
			return {
				is_phishing: true,
				confidence: 0.0,
				features: {},
				whitelisted: false,
				threat_level: 'high'
			};
		}
	}
}

const analyzer = new URLFeatureExtractor();

// Create a notification system
function showToast(result) {
	const options = {
		type: 'basic',
		iconUrl: 'icons/icon128.png',
		title: result.is_phishing ? 'Warning: Potentially Unsafe Website' : 'Safe Website',
		message: `Threat Level: ${result.threat_level.toUpperCase()}\nConfidence: ${Math.round(result.confidence * 100)}%`
	};

	chrome.notifications.create('urlScan_' + Date.now(), options);
}

// Track previously scanned URLs to avoid duplicate notifications
const scannedUrls = new Set();

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
	if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
		// Check if URL was recently scanned
		if (!scannedUrls.has(tab.url)) {
			const result = analyzer.predictUrl(tab.url);
			
			// Show notification based on threat level
			if (result.threat_level === 'high' || result.threat_level === 'medium') {
				showToast(result);
			}

			// Add URL to recently scanned set
			scannedUrls.add(tab.url);

			// Clear URL from set after 5 minutes to allow rescanning
			setTimeout(() => {
				scannedUrls.delete(tab.url);
			}, 5 * 60 * 1000);

			// Update extension icon and badge based on threat level
			const iconColor = result.is_phishing ? '#FF0084' : '#00FFA9';
			chrome.action.setBadgeBackgroundColor({ color: iconColor });
			chrome.action.setBadgeText({ 
				text: result.threat_level === 'safe' ? '✓' : '!',
				tabId: tabId
			});
		}
	}
});

// Existing message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
	if (request.action === 'analyzeUrl') {
		const result = analyzer.predictUrl(request.url);
		sendResponse(result);
	}
	return true;
});