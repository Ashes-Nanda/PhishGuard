import { CyberCellReport, AnonymousTip } from '../types';
import { collections } from '../config/firebase';

export const saveReport = async (report: CyberCellReport): Promise<void> => {
  try {
    await collections.cyberCellReports.doc(report.reference_id).set({
      referenceId: report.reference_id,
      url: report.url,
      threatType: report.threat_type,
      evidence: report.evidence,
      reporterInfo: report.reporter_info || null,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error saving cyber cell report:', error);
    throw new Error('Failed to save report to database');
  }
};

export const saveTip = async (tip: AnonymousTip): Promise<void> => {
  try {
    await collections.anonymousTips.doc(tip.tip_id).set({
      tipId: tip.tip_id,
      tipType: tip.tip_type,
      content: tip.content,
      additionalDetails: tip.additional_details || null,
      evidenceUrls: tip.evidence_urls,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error saving anonymous tip:', error);
    throw new Error('Failed to save tip to database');
  }
};

export const saveScanHistory = async (scanResult: any): Promise<void> => {
  try {
    const historyItem = {
      url: scanResult.url,
      timestamp: new Date(),
      isSafe: scanResult.isSafe,
      threats: scanResult.threats,
      severity: scanResult.severity,
      categories: scanResult.categories,
      detectionCount: scanResult.detectionCount
    };
    
    await collections.scanHistory.add(historyItem);
  } catch (error) {
    console.error('Error saving scan history:', error);
    throw new Error('Failed to save scan history');
  }
};

export const getScanHistory = async (limit: number = 50): Promise<any[]> => {
  try {
    const snapshot = await collections.scanHistory
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();
      
    return snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
  } catch (error) {
    console.error('Error fetching scan history:', error);
    throw new Error('Failed to fetch scan history');
  }
}; 