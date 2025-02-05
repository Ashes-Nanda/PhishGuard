declare module 'tld-extract' {
    export function extract(url: string): {
        subdomain: string;
        domain: string;
        tld: string;
    };
} 