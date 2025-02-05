import { Router } from 'express';
import { collections } from '../config/firebase';
import { URLFeatureExtractor } from '../ml_model/URLFeatureExtractor';

const router = Router();
const urlFeatureExtractor = new URLFeatureExtractor();

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

    // Perform ML model analysis
    const mlResult = await urlFeatureExtractor.predict_url(url);
    
    // Prepare final result
    const result = {
      url,
      isSafe: !mlResult.is_phishing,
      confidence: mlResult.confidence || 0.5,
      mlConfidence: mlResult.confidence || 0.5,
      vtConfidence: 0.5, // Default value since VT integration is not implemented yet
      message: mlResult.is_phishing ? 
        "Warning: This URL shows signs of being malicious" : 
        "This URL appears to be safe",
      severity: mlResult.is_phishing ? "high" : "low",
      categories: [mlResult.is_phishing ? "phishing" : "safe"],
      threats: mlResult.is_phishing ? ["ML Model: Potential phishing URL detected"] : [],
      detectionCount: {
        phishing: mlResult.is_phishing ? 1 : 0,
        malware: 0,
        suspicious: mlResult.is_phishing ? 1 : 0,
        malicious: mlResult.is_phishing ? 1 : 0
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