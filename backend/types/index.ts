export interface CyberCellReport {
  reference_id?: string;
  url: string;
  threat_type: string;
  evidence: {
    scan_result: any;
    detection_counts: number;
    threats: string[];
  };
  reporter_info?: {
    name?: string;
    contact?: string;
    location?: string;
  };
  timestamp?: Date;
}

export interface AnonymousTip {
  tip_id?: string;
  tip_type: 'URL' | 'SMS' | 'EMAIL' | 'OTHER';
  content: string;
  additional_details?: string;
  evidence_urls: string[];
  timestamp?: Date;
}

export interface EmailNotification {
  to: string;
  subject: string;
  template: string;
  data: any;
} 