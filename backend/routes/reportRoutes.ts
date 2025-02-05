import { Router } from 'express';
import { collections } from '../config/firebase';
import { sendEmailNotification } from '../utils/notifications';
import { validateReport, validateTip } from '../utils/validation';
import { CyberCellReport, AnonymousTip } from '../types';

const router = Router();

// Report to MP Cyber Cell
router.post('/report-to-cybercell', async (req, res) => {
  try {
    const report: CyberCellReport = req.body;
    
    if (!validateReport(report)) {
      return res.status(400).json({ error: 'Invalid report data' });
    }

    // Save report to database
    const reportRef = await collections.cyberCellReports.add({
      ...report,
      timestamp: new Date(),
      status: 'pending'
    });

    // Send notification to Cyber Cell
    if (process.env.CYBER_CELL_EMAIL) {
      await sendEmailNotification({
        to: process.env.CYBER_CELL_EMAIL,
        subject: `New Cyber Threat Report - Ref: ${reportRef.id}`,
        template: 'cyber-cell-report',
        data: { ...report, reference_id: reportRef.id }
      });
    }

    // Send confirmation to reporter if contact info provided
    if (report.reporter_info?.contact) {
      await sendEmailNotification({
        to: report.reporter_info.contact,
        subject: 'Your Cyber Threat Report - Confirmation',
        template: 'report-confirmation',
        data: { reference_id: reportRef.id, report }
      });
    }

    res.json({
      success: true,
      reference_id: reportRef.id,
      message: 'Report submitted successfully to MP Cyber Cell'
    });

  } catch (error) {
    console.error('Error submitting cyber cell report:', error);
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

// Submit anonymous tip
router.post('/submit-anonymous-tip', async (req, res) => {
  try {
    const tip: AnonymousTip = req.body;
    
    if (!validateTip(tip)) {
      return res.status(400).json({ error: 'Invalid tip data' });
    }

    // Save tip to database
    const tipRef = await collections.anonymousTips.add({
      ...tip,
      timestamp: new Date(),
      status: 'pending'
    });

    // Send notification to authorities
    if (process.env.CYBER_CELL_TIPS_EMAIL) {
      await sendEmailNotification({
        to: process.env.CYBER_CELL_TIPS_EMAIL,
        subject: `New Anonymous Tip - ID: ${tipRef.id}`,
        template: 'anonymous-tip',
        data: { ...tip, tip_id: tipRef.id }
      });
    }

    res.json({
      success: true,
      tip_id: tipRef.id,
      message: 'Anonymous tip submitted successfully'
    });

  } catch (error) {
    console.error('Error submitting anonymous tip:', error);
    res.status(500).json({ error: 'Failed to submit tip' });
  }
});

export default router; 