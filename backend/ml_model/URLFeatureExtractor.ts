import axios from 'axios';
import { URL } from 'url';
import { extract } from 'tld-extract';
import { DateTime } from 'luxon';

export class URLFeatureExtractor {
    private whitelist: Set<string>;

    constructor() {
        // Initialize whitelist of known legitimate domains
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
            return response.protocol === 'https:' ? 1 : -1;
        } catch {
            return -1;
        }
    }

    private extract_features(url: string): number[] {
        const features = new Array(31).fill(0);
        
        features[0] = this.have_ip_address(url);
        features[1] = this.url_length(url);
        features[2] = this.url_shortener(url);
        features[3] = this.have_at_symbol(url);
        features[4] = this.double_slash_redirect(url);
        features[5] = this.prefix_suffix(url);
        features[6] = this.have_subdomain(url);
        
        return features;
    }

    public async predict_url(url: string): Promise<any> {
        try {
            // Normalize URL
            if (!url.startsWith('http')) {
                url = 'http://' + url;
            }

            // Parse URL
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const cleanDomain = domain.startsWith('www.') ? domain.slice(4) : domain;

            // Check whitelist
            if (this.whitelist.has(cleanDomain) || this.whitelist.has(domain)) {
                return {
                    is_phishing: false,
                    confidence: 1.0,
                    features: {},
                    whitelisted: true
                };
            }

            // Extract features
            const features = this.extract_features(url);
            const sslScore = await this.check_ssl(url);
            features.push(sslScore);

            // Calculate confidence score
            const negativeFeatures = features.filter(f => f === -1).length;
            const totalFeatures = features.filter(f => f !== 0).length;
            const confidence = totalFeatures > 0 ? 
                1 - (negativeFeatures / totalFeatures) : 0.5;

            const activeFeatures = {
                has_ip_address: features[0] === -1,
                long_url: features[1] === -1,
                uses_shortener: features[2] === -1,
                has_at_symbol: features[3] === -1,
                has_double_slash: features[4] === -1,
                has_prefix_suffix: features[5] === -1,
                has_multiple_subdomains: features[6] === -1,
                no_ssl: sslScore === -1
            };

            return {
                is_phishing: confidence < 0.6,
                confidence: confidence,
                features: activeFeatures,
                whitelisted: false,
                timestamp: DateTime.now().toISO()
            };

        } catch (error) {
            console.error('Prediction error:', error);
            return {
                is_phishing: false,
                confidence: 0.0,
                features: {},
                whitelisted: false,
                timestamp: DateTime.now().toISO()
            };
        }
    }
} 