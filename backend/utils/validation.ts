import { CyberCellReport, AnonymousTip } from '../types';
import validator from 'validator';

export const validateReport = (report: CyberCellReport): boolean => {
  // Required fields
  if (!report.url || !report.threat_type || !report.evidence) {
    return false;
  }

  // URL validation
  if (!validator.isURL(report.url)) {
    return false;
  }

  // Evidence validation
  if (!report.evidence.scan_result || 
      typeof report.evidence.detection_counts !== 'number' ||
      !Array.isArray(report.evidence.threats)) {
    return false;
  }

  // Optional reporter info validation
  if (report.reporter_info) {
    const { contact } = report.reporter_info;
    if (contact && !validator.isEmail(contact) && !validator.isMobilePhone(contact, 'any')) {
      return false;
    }
  }

  return true;
};

export const validateTip = (tip: AnonymousTip): boolean => {
  // Required fields
  if (!tip.tip_type || !tip.content) {
    return false;
  }

  // Tip type validation
  const validTipTypes = ['URL', 'SMS', 'EMAIL', 'OTHER'];
  if (!validTipTypes.includes(tip.tip_type)) {
    return false;
  }

  // Content length validation
  if (tip.content.length < 10 || tip.content.length > 5000) {
    return false;
  }

  // Evidence URLs validation
  if (tip.evidence_urls) {
    if (!Array.isArray(tip.evidence_urls)) {
      return false;
    }
    for (const url of tip.evidence_urls) {
      if (!validator.isURL(url)) {
        return false;
      }
    }
  }

  return true;
}; 