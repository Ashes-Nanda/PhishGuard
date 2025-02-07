import axios from 'axios';
import { URL } from 'url';
import { extract } from 'tld-extract';
import { DateTime } from 'luxon';

interface PredictionResult {
    is_phishing: boolean;
    confidence: number;
    features: Record<string, boolean>;
    whitelisted: boolean;
    timestamp: string;
    threat_level?: 'high' | 'medium' | 'low' | 'safe';
}

interface FeatureWeights {
    has_ip_address: number;
    long_url: number;
    uses_shortener: number;
    has_at_symbol: number;
    has_double_slash: number;
    has_prefix_suffix: number;
    has_multiple_subdomains: number;
    has_suspicious_keywords: number;
    has_suspicious_tld: number;
    has_numeric_subdomain: number;
    has_random_subdomain: number;
    no_ssl: number;
    encoding_techniques: number;
    typosquatting: number;
    redirect_chains: number;
}

export class URLFeatureExtractor {
    private whitelist: Set<string>;
    private readonly weights: FeatureWeights = {
        has_ip_address: 3.0,
        long_url: 1.0,
        uses_shortener: 2.0,
        has_at_symbol: 1.5,
        has_double_slash: 1.5,
        has_prefix_suffix: 1.0,
        has_multiple_subdomains: 2.0,
        has_suspicious_keywords: 3.0,
        has_suspicious_tld: 3.0,
        has_numeric_subdomain: 2.0,
        has_random_subdomain: 2.0,
        no_ssl: 2.5,
        encoding_techniques: 2.0,
        typosquatting: 3.5,
        redirect_chains: 2.0
    };

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
    }


    private async checkAlexaRank(domain: string): Promise<number> {
        try {
            const response = await axios.get(`http://data.alexa.com/data?cli=10&url=${domain}`);
            const rank = parseInt(response.data.match(/<REACH RANK="(\d+)"/)[1]);
            return rank > 1000000 ? -1 : 1;
        } catch {
            return -1;
        }
    }

    private checkEncodingTechniques(url: string): number {
        const suspiciousEncoding = /%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}/;
        return suspiciousEncoding.test(url) ? -1 : 1;
    }

    private checkTyposquatting(domain: string): number {
        const commonTypos = {
            'google': /g[o0]{1,2}gle|go{2,}gle|g0{2,}gle/i,
            'facebook': /f[a@]ce?b[o0]{1,2}k|faceb[o0]{2,}k/i,
            'microsoft': /micr[o0]s[o0]ft|micros[o0]ft|micr[o0]soft/i,
            'apple': /[a@]pple|ap+le/i,
            'amazon': /amaz[o0]n|am[a@]z[o0]n/i,
            'paypal': /p[a@]yp[a@]l|p[a@]yp[a@]ll/i,
            'netflix': /n[e3]tfl[i1]x|netfl[i1]x/i,
            'instagram': /[i1]nst[a@]gr[a@]m/i
        };

        // Check for number substitutions (like 0 for o)
        const hasNumberSubstitution = /[0-9]/.test(domain);
        
        // Check for character repetition (like googgle)
        const hasCharRepetition = /(.)\1{2,}/.test(domain);

        for (const [legitimate, pattern] of Object.entries(commonTypos)) {
            if (pattern.test(domain) && domain.toLowerCase() !== legitimate) {
                return -1;
            }
        }

        // If there are number substitutions or character repetitions, consider it suspicious
        if (hasNumberSubstitution || hasCharRepetition) {
            return -1;
        }

        return 1;
    }

    private async checkRedirectChains(url: string): Promise<number> {
        try {
            let redirectCount = 0;
            let currentUrl = url;
            
            for (let i = 0; i < 5; i++) {
                const response = await axios.head(currentUrl, {
                    maxRedirects: 0,
                    validateStatus: null
                });
                
                if (response.status >= 300 && response.status < 400 && response.headers.location) {
                    redirectCount++;
                    currentUrl = response.headers.location;
                } else {
                    break;
                }
            }
            
            return redirectCount > 2 ? -1 : 1;
        } catch {
            return -1;
        }
    }

    private have_ip_address(url: string): number {
        const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        return ipPattern.test(url) ? -1 : 1;
    }

    private url_length(url: string): number {
        if (url.length < 54) return 1;
        if (url.length >= 54 && url.length <= 75) return 0;
        return -1;
    }

    private url_shortener(url: string): number {
        const shortenerPattern = /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd/i;
        return shortenerPattern.test(url) ? -1 : 1;
    }

    private have_at_symbol(url: string): number {
        return url.includes('@') ? -1 : 1;
    }

    private double_slash_redirect(url: string): number {
        const lastSlashIndex = url.lastIndexOf('//');
        return lastSlashIndex > 6 ? -1 : 1;
    }

    private prefix_suffix(url: string): number {
        return url.includes('-') ? -1 : 1;
    }

    private have_subdomain(url: string): number {
        try {
            const { subdomain } = extract(url);
            if (!subdomain) return 1;
            const subdomains = subdomain.split('.');
            if (subdomains.length <= 1) return 1;
            if (subdomains.length === 2) return 0;
            return -1;
        } catch {
            return -1;
        }
    }

    private async check_ssl(url: string): Promise<number> {
        try {
            const response = await axios.head(url, {
                timeout: 5000,
                validateStatus: null
            });
            return url.startsWith('https://') ? 1 : -1;
        } catch {
            return -1;
        }
    }

    private async extract_features(url: string): Promise<number[]> {
        const features = new Array(15).fill(0);
        
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();

            features[0] = this.have_ip_address(url);
            features[1] = this.url_length(url);
            features[2] = this.url_shortener(url);
            features[3] = this.have_at_symbol(url);
            features[4] = this.double_slash_redirect(url);
            features[5] = this.prefix_suffix(url);
            features[6] = this.have_subdomain(url);
            features[7] = /login|account|secure|verify|signin|security|update/i.test(hostname) ? -1 : 1;
            features[8] = /.+\.(xyz|tk|ml|ga|cf|gq|pw)$/i.test(hostname) ? -1 : 1;
            features[9] = /^[0-9-]+\./.test(hostname) ? -1 : 1;
            features[10] = /^[a-z0-9]{8,}\./.test(hostname) ? -1 : 1;
            features[11] = this.checkEncodingTechniques(url);
            features[12] = this.checkTyposquatting(hostname);
            features[13] = await this.checkRedirectChains(url);
            features[14] = await this.check_ssl(url);
        } catch (error) {
            console.error('Feature extraction error:', error);
            return features.map(() => -1); // Mark all features as suspicious on error
        }
        
        return features;

    }

    public async predict_url(url: string): Promise<PredictionResult> {
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
                    timestamp: DateTime.now().toISO(),
                    threat_level: 'safe'
                };
            }

            const features = await this.extract_features(url);
            
            const activeFeatures: Record<string, boolean> = {
                has_ip_address: features[0] === -1,
                long_url: features[1] === -1,
                uses_shortener: features[2] === -1,
                has_at_symbol: features[3] === -1,
                has_double_slash: features[4] === -1,
                has_prefix_suffix: features[5] === -1,
                has_multiple_subdomains: features[6] === -1,
                has_suspicious_keywords: features[7] === -1,
                has_suspicious_tld: features[8] === -1,
                has_numeric_subdomain: features[9] === -1,
                has_random_subdomain: features[10] === -1,
                encoding_techniques: features[11] === -1,
                typosquatting: features[12] === -1,
                redirect_chains: features[13] === -1,
                no_ssl: features[14] === -1
            };

            let weightedNegativeScore = 0;
            let totalWeight = 0;

            Object.entries(activeFeatures).forEach(([feature, isNegative]) => {
                const weight = this.weights[feature as keyof FeatureWeights];
                if (isNegative) weightedNegativeScore += weight;
                totalWeight += weight;
            });

            const confidence = totalWeight > 0 ? 
                1 - (weightedNegativeScore / totalWeight) : 0.5;

            const threat_level = confidence < 0.5 ? 'high' :
                               confidence < 0.7 ? 'medium' :
                               confidence < 0.85 ? 'low' : 'safe';

            return {
                is_phishing: confidence < 0.85,
                confidence,
                features: activeFeatures,
                whitelisted: false,
                timestamp: DateTime.now().toISO(),
                threat_level
            };

        } catch (error) {
            console.error('Prediction error:', error);
            return {
                is_phishing: true,
                confidence: 0.0,
                features: {},
                whitelisted: false,
                timestamp: DateTime.now().toISO(),
                threat_level: 'high'
            };
        }

    }
} 