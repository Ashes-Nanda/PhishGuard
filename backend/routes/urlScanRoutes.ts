import { Router } from 'express';
import { collections } from '../config/firebase';
import { URLFeatureExtractor } from '../ml_model/URLFeatureExtractor';
import axios from 'axios';

const router = Router();
const urlFeatureExtractor = new URLFeatureExtractor();
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

async function checkVirusTotal(url: string): Promise<{
  isClean: boolean;
  confidence: number;
  detections: number;
}> {
  try {
    if (!VIRUSTOTAL_API_KEY) {
      console.warn('VirusTotal API key not configured');
      return { isClean: true, confidence: 0.5, detections: 0 };
    }

    const response = await axios.post(
      'https://www.virustotal.com/vtapi/v2/url/report',
      null,
      {
        params: {
          apikey: VIRUSTOTAL_API_KEY,
          resource: url
        }
      }
    );

    const { data } = response;
    const totalScans = Object.keys(data.scans || {}).length;
    const positives = data.positives || 0;
    const confidence = totalScans > 0 ? 1 - (positives / totalScans) : 0.5;

    return {
      isClean: positives === 0,
      confidence,
      detections: positives
    };
  } catch (error) {
    console.error('VirusTotal API error:', error);
    return { isClean: true, confidence: 0.5, detections: 0 };
  }
}

// Get known phishing URLs
router.get('/known-phishing-urls', async (req, res) => {
  try {
    const snapshot = await collections.scanHistory
      .where('isSafe', '==', false)
      .orderBy('timestamp', 'desc')
      .limit(1000)
      .get();

    const urls = snapshot.docs.map(doc => doc.data().url).filter(Boolean);
    res.json({ urls });
  } catch (error) {
    console.error('Error fetching known phishing URLs:', error);
    res.status(500).json({ error: 'Failed to fetch known phishing URLs' });
  }
});

router.post('/scan-url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Store scan request in history
    const scanRef = await collections.scanHistory.add({
      url,
      timestamp: new Date(),
      status: 'pending'
    });

    // Perform both checks in parallel
    const [mlResult, vtResult] = await Promise.all([
      urlFeatureExtractor.predict_url(url),
      checkVirusTotal(url)
    ]);
    
    // Combined threat assessment
    const isSafe = mlResult.is_phishing === false && vtResult.isClean === true;
    const combinedConfidence = (mlResult.confidence + vtResult.confidence) / 2;

    const result = {
      url,
      isSafe,
      confidence: combinedConfidence,
      mlConfidence: mlResult.confidence,
      vtConfidence: vtResult.confidence,
      message: isSafe ? 
        "This URL appears to be safe" : 
        "Warning: This URL shows signs of being malicious",
      severity: isSafe ? "low" : "high",
      categories: [
        ...(mlResult.is_phishing ? ["phishing"] : []),
        ...(vtResult.detections > 0 ? ["malicious"] : [])
      ],
      threats: [
        ...(mlResult.is_phishing ? ["ML Model: Potential phishing URL detected"] : []),
        ...(vtResult.detections > 0 ? [`VirusTotal: ${vtResult.detections} security vendors flagged this URL`] : [])
      ],
      detectionCount: {
        phishing: mlResult.is_phishing ? 1 : 0,
        malware: vtResult.detections > 0 ? 1 : 0,
        suspicious: (mlResult.is_phishing || vtResult.detections > 0) ? 1 : 0,
        malicious: vtResult.detections
      },
      timestamp: new Date().toISOString()
    };

    // Update scan history with results
    await scanRef.update({
      status: 'completed',
      ...result
    });

    // Send response
    res.json(result);

  } catch (error) {
    console.error('Error scanning URL:', error);
    res.status(500).json({ error: 'Failed to scan URL' });
  }
});

router.get('/history', async (req, res) => {
  try {
    const historySnapshot = await collections.scanHistory
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();

    const history = historySnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(history);
  } catch (error) {
    console.error('Error fetching scan history:', error);
    res.status(500).json({ error: 'Failed to fetch scan history' });
  }
});

export default router; 