import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  Button,
  Container,
  Heading,
  Input,
  VStack,
  Text,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  useToast,
  Icon,
  Tooltip,
  HStack,
  Spinner,
  Badge,
  SimpleGrid,
  Progress,
  IconButton,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  List,
  ListItem,
  ListIcon,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Divider,
  Link as ChakraLink,
  FormControl,
  FormLabel,
  Textarea,
  Wrap,
  WrapItem,
  Select,
} from '@chakra-ui/react';
import { motion } from 'framer-motion';
import { FaShieldAlt, FaInfoCircle, FaExclamationTriangle, FaCopy, FaShare, FaHistory, FaRedoAlt, FaExclamationCircle, FaCheckCircle, FaBookReader, FaShieldVirus, FaLock, FaFlag, FaUserShield, FaCrown, FaCalendarCheck, FaRobot, FaUserSecret } from 'react-icons/fa';
import { keyframes } from '@emotion/react';
import DOMPurify from 'dompurify';
import { useNavigate } from 'react-router-dom';
import { IconType } from 'react-icons';

const MotionBox = motion(Box);

interface ScanResult {
  isSafe: boolean;
  threats: string[];
  message: string;
  severity: string;
  categories: string[];
  detectionCount: {
    phishing: number;
    malware: number;
    suspicious: number;
    malicious: number;
  };
  confidence: number;
  mlConfidence: number;
  vtConfidence: number;
  timestamp?: string;
  url?: string;
  lastSeen?: string;
  domainAge?: string;
  tipId?: string;
  whitelisted?: boolean;
}

interface PhishingIndicator {
  type: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  educationalTip: string;
}

interface SecurityTip {
  title: string;
  description: string;
  category: string;
}

interface UserBadge {
  id: string;
  name: string;
  description: string;
  icon: IconType;
  criteria: string;
  earned: boolean;
}

interface PhishingTip {
  id: string;
  title: string;
  content: string;
  category: string;
}

interface QuickScanResult {
  isSuspicious: boolean;
  reason?: string;
}

interface CyberCellReport {
  url: string;
  threat_type: string;
  evidence: any;
  reporter_info?: {
    name?: string;
    contact?: string;
    location?: string;
  };
}

interface AnonymousTip {
  tip_type: string;
  content: string;
  additional_details?: string;
  evidence_urls: string[];
}

const QUICK_CHECK_PATTERNS = {
  suspiciousKeywords: ['login', 'verify', 'account', 'secure', 'banking', 'password'],
  commonTLDs: ['.com', '.org', '.net', '.edu', '.gov'],
  suspiciousTLDs: ['.xyz', '.tk', '.ml', '.ga', '.cf'],
};

const MAX_URL_LENGTH = 2048; // Common maximum URL length
const URL_REGEX = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
const RATE_LIMIT_DURATION = 60 * 1000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_DURATION = 5; // Maximum 5 requests per minute

const pulseAnimation = keyframes`
  0% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.1); opacity: 0.8; }
  100% { transform: scale(1); opacity: 1; }
`;

const floatingButtonStyles = {
  position: 'fixed',
  bottom: '2rem',
  right: '2rem',
  zIndex: 10,
  boxShadow: 'lg',
  borderRadius: 'full',
  width: '60px',
  height: '60px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  cursor: 'pointer',
  transition: 'all 0.2s',
  _hover: {
    transform: 'scale(1.1)',
  },
  _active: {
    transform: 'scale(0.95)',
  },
};

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    console.error('Failed to copy:', err);
    return false;
  }
};

interface RateLimit {
  count: number;
  firstRequest: number;
}

const SECURITY_TIPS: SecurityTip[] = [
  {
    title: 'Check the URL carefully',
    description: 'Look for misspellings, unusual characters, or numbers replacing letters.',
    category: 'url',
  },
  {
    title: 'Verify SSL/TLS certificates',
    description: 'Ensure the website has a valid security certificate (look for the padlock icon).',
    category: 'security',
  },
  {
    title: 'Be wary of urgent requests',
    description: 'Phishers often create a false sense of urgency to make you act quickly.',
    category: 'social',
  },
];

const BADGES: UserBadge[] = [
  {
    id: 'first_report',
    name: 'First Line of Defense',
    description: 'Reported your first suspicious URL',
    icon: FaShieldAlt,
    criteria: 'Report 1 suspicious URL',
    earned: false,
  },
  {
    id: 'vigilant_reporter',
    name: 'Vigilant Reporter',
    description: 'Reported 5 suspicious URLs',
    icon: FaUserShield,
    criteria: 'Report 5 suspicious URLs',
    earned: false,
  },
  {
    id: 'security_expert',
    name: 'Security Expert',
    description: 'Reported 10 confirmed malicious URLs',
    icon: FaCrown,
    criteria: 'Report 10 confirmed malicious URLs',
    earned: false,
  },
  {
    id: 'daily_scanner',
    name: 'Daily Scanner',
    description: 'Used the scanner for 7 consecutive days',
    icon: FaCalendarCheck,
    criteria: 'Scan URLs for 7 consecutive days',
    earned: false,
  }
];

const PHISHING_TIPS: PhishingTip[] = [
  {
    id: 'tip1',
    title: 'Check the Sender',
    content: 'Verify the email address or website domain carefully. Scammers often use slight misspellings.',
    category: 'email',
  },
  {
    id: 'tip2',
    title: 'Hover Before Clicking',
    content: 'Hover over links to preview their true destination before clicking.',
    category: 'links',
  },
  {
    id: 'tip3',
    title: 'Beware of Urgency',
    content: 'Be suspicious of messages creating a sense of urgency or threatening consequences.',
    category: 'social',
  },
  {
    id: 'tip4',
    title: 'Check for HTTPS',
    content: 'Ensure sensitive websites use HTTPS and have a valid security certificate.',
    category: 'technical',
  }
];

const formatConfidenceScore = (confidence: number): string => {
  if (typeof confidence !== 'number' || isNaN(confidence)) {
    return '0%';
  }
  return `${Math.round(confidence * 100)}%`;
};

const formatScanDate = (timestamp: string | number): string => {
  try {
    // Handle Unix timestamp (in seconds)
    if (typeof timestamp === 'number') {
      return new Date(timestamp * 1000).toLocaleString();
    }
    // Handle ISO string
    return new Date(timestamp).toLocaleString();
  } catch (e) {
    return 'Unknown Date';
  }
};

export const URLScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [showShareOptions, setShowShareOptions] = useState(false);
  const toast = useToast();
  const [rateLimit, setRateLimit] = useState<RateLimit>({ count: 0, firstRequest: Date.now() });
  const navigate = useNavigate();
  const [showEducation, setShowEducation] = useState(false);
  const [educationalContent, setEducationalContent] = useState<PhishingIndicator[]>([]);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportReason, setReportReason] = useState('');
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);
  const [userBadges, setUserBadges] = useState<UserBadge[]>(() => {
    const saved = localStorage.getItem('userBadges');
    return saved ? JSON.parse(saved) : BADGES;
  });
  const [showBadgeModal, setShowBadgeModal] = useState(false);
  const [newBadge, setNewBadge] = useState<UserBadge | null>(null);
  const [currentTip, setCurrentTip] = useState<PhishingTip | null>(null);
  const [offlineDB, setOfflineDB] = useState<Set<string>>(() => {
    const saved = localStorage.getItem('offlinePhishingDB');
    return new Set(saved ? JSON.parse(saved) : []);
  });
  const [quickResult, setQuickResult] = useState<QuickScanResult | null>(null);
  const [isQuickScanning, setIsQuickScanning] = useState(false);
  const [showCyberCellModal, setShowCyberCellModal] = useState(false);
  const [showAnonymousTipModal, setShowAnonymousTipModal] = useState(false);
  const [reporterInfo, setReporterInfo] = useState({ name: '', contact: '', location: '' });
  const [anonymousTip, setAnonymousTip] = useState({
    tip_type: 'URL',
    content: '',
    additional_details: '',
    evidence_urls: []
  });

  const sanitizeUrl = (input: string): string => {
    const sanitized = DOMPurify.sanitize(input, { ALLOWED_TAGS: [] });
    return sanitized.replace(/[^\w\s-._~:/?#\[\]@!$&'()*+,;=]/gi, '');
  };

  const checkRateLimit = (): boolean => {
    const now = Date.now();
    if (now - rateLimit.firstRequest > RATE_LIMIT_DURATION) {
      setRateLimit({ count: 1, firstRequest: now });
      return true;
    }
    
    if (rateLimit.count >= MAX_REQUESTS_PER_DURATION) {
      toast({
        title: 'Rate Limit Exceeded',
        description: `Please wait ${Math.ceil((RATE_LIMIT_DURATION - (now - rateLimit.firstRequest)) / 1000)} seconds before trying again`,
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
      return false;
    }
    
    setRateLimit(prev => ({ ...prev, count: prev.count + 1 }));
    return true;
  };

  const analyzeUrlForEducation = (url: string): PhishingIndicator[] => {
    const indicators: PhishingIndicator[] = [];
    
    if (url.includes('bit.ly') || url.includes('tinyurl')) {
      indicators.push({
        type: 'URL Shortener',
        description: 'This URL uses a shortening service which can hide the actual destination.',
        severity: 'medium',
        educationalTip: 'Always expand shortened URLs before visiting them.',
      });
    }
    
    if (url.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)) {
      indicators.push({
        type: 'IP Address URL',
        description: 'This URL uses an IP address instead of a domain name.',
        severity: 'high',
        educationalTip: 'Legitimate websites typically use domain names, not IP addresses.',
      });
    }
    
    return indicators;
  };

  const performQuickScan = (urlToCheck: string): QuickScanResult => {
    if (checkOfflineDB(urlToCheck)) {
      return {
        isSuspicious: true,
        reason: 'URL found in local phishing database'
      };
    }

    const hasSuspiciousTLD = QUICK_CHECK_PATTERNS.suspiciousTLDs.some(tld => 
      urlToCheck.toLowerCase().endsWith(tld)
    );
    if (hasSuspiciousTLD) {
      return {
        isSuspicious: true,
        reason: 'Suspicious domain extension detected'
      };
    }

    const hasKeywords = QUICK_CHECK_PATTERNS.suspiciousKeywords.some(keyword =>
      urlToCheck.toLowerCase().includes(keyword)
    );
    if (hasKeywords) {
      return {
        isSuspicious: true,
        reason: 'Contains suspicious keywords'
      };
    }

    if (urlToCheck.match(/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
      return {
        isSuspicious: true,
        reason: 'Uses IP address instead of domain name'
      };
    }

    return { isSuspicious: false };
  };

  const handleScan = async () => {
    if (!url) {
      toast({
        title: 'Please enter a URL',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    // Prevent multiple scans while one is in progress
    if (isScanning || isQuickScanning) {
      return;
    }

    setIsQuickScanning(true);
    const sanitizedUrl = sanitizeUrl(url);
    const urlToScan = sanitizedUrl.startsWith('http') ? sanitizedUrl : `https://${sanitizedUrl}`;

    try {
      // Perform quick scan
      const quickScanResult = performQuickScan(urlToScan);
      setQuickResult(quickScanResult);

      if (quickScanResult.isSuspicious) {
        toast({
          title: 'Quick Check Warning',
          description: quickScanResult.reason,
          status: 'warning',
          duration: 5000,
          isClosable: true,
        });
      }

      // Start main scan
      setIsQuickScanning(false);
      setIsScanning(true);

      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ url: urlToScan })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const result = await response.json();
      
      // Update state and save history only if we have a valid result
      if (result && typeof result.isSafe !== 'undefined') {
        setScanResult(result);
        saveToHistory(result);

        toast({
          title: result.isSafe ? 'URL is Safe' : 'Warning: Potential Threat',
          description: result.message,
          status: result.isSafe ? 'success' : 'error',
          duration: 5000,
          isClosable: true,
        });
      }

    } catch (error) {
      console.error('Scan error:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to scan URL. Please try again.',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setIsScanning(false);
      setIsQuickScanning(false);
    }
  };

  const handleCopy = async () => {
    if (scanResult?.url) {
      const success = await copyToClipboard(scanResult.url);
      toast({
        title: success ? 'URL Copied!' : 'Failed to copy URL',
        status: success ? 'success' : 'error',
        duration: 2000,
        isClosable: true,
      });
    }
  };

  const handleShare = async () => {
    if (scanResult) {
      try {
        await navigator.share({
          title: 'URL Scan Result',
          text: `URL Security Scan Result for: ${scanResult.url}\nStatus: ${
            scanResult.isSafe ? 'Safe' : 'Potentially Unsafe'
          }\nMessage: ${scanResult.message}`,
          url: window.location.href,
        });
      } catch (err) {
        console.error('Share failed:', err);
        setShowShareOptions(true);
      }
    }
  };

  const handleRescan = () => {
    if (scanResult?.url) {
      setUrl(scanResult.url);
      handleScan();
    }
  };

  const saveToHistory = (result: ScanResult) => {
    const historyItem = {
      url: result.url,
      timestamp: result.timestamp,
      isSafe: result.isSafe,
      message: result.message,
      severity: result.severity,
    };

    const savedHistory = localStorage.getItem('scanHistory');
    const history = savedHistory ? JSON.parse(savedHistory) : [];
    
    history.unshift(historyItem);
    
    const trimmedHistory = history.slice(0, 50);
    
    localStorage.setItem('scanHistory', JSON.stringify(trimmedHistory));
  };

  const handleReportFalsePositive = async () => {
    if (scanResult) {
      setIsSubmittingReport(true);
      try {
        const response = await fetch('/api/report-false-positive', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: scanResult.url,
            reason: reportReason,
          }),
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        toast({
          title: result.isSuccess ? 'Report Submitted' : 'Report Submission Error',
          description: result.message,
          status: result.isSuccess ? 'success' : 'error',
          duration: 5000,
          isClosable: true,
        });

        if (result.isSuccess) {
          setReportReason('');
          setShowReportModal(false);

          const reportCount = parseInt(localStorage.getItem('reportCount') || '0') + 1;
          localStorage.setItem('reportCount', reportCount.toString());
          updateBadges(reportCount);
          
          const newOfflineDB = new Set(offlineDB);
          newOfflineDB.add(scanResult!.url!);
          setOfflineDB(newOfflineDB);
          localStorage.setItem('offlinePhishingDB', JSON.stringify(Array.from(newOfflineDB)));
        }
      } catch (error) {
        console.error('Report submission error:', error);
        toast({
          title: 'Error',
          description: 'Failed to submit report. Please try again later.',
          status: 'error',
          duration: 5000,
          isClosable: true,
        });
      } finally {
        setIsSubmittingReport(false);
      }
    }
  };

  const handleCyberCellReport = async () => {
    if (!scanResult) return;

    try {
      const report: CyberCellReport = {
        url: scanResult.url!,
        threat_type: scanResult.categories[0] || 'suspicious',
        evidence: {
          scan_result: scanResult,
          detection_counts: scanResult.detectionCount,
          threats: scanResult.threats
        },
        reporter_info: reporterInfo
      };

      const response = await fetch('/api/report-to-cybercell', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(report)
      });

      if (!response.ok) throw new Error('Failed to submit report');

      const result = await response.json();
      toast({
        title: 'Report Submitted',
        description: `Successfully reported to MP Cyber Cell. Reference ID: ${result.reference_id}`,
        status: 'success',
        duration: 5000,
        isClosable: true
      });

      setShowCyberCellModal(false);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to submit report to MP Cyber Cell',
        status: 'error',
        duration: 5000,
        isClosable: true
      });
    }
  };

  const handleAnonymousTip = async () => {
    try {
      const response = await fetch('/api/submit-anonymous-tip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(anonymousTip)
      });

      if (!response.ok) throw new Error('Failed to submit tip');

      const result = await response.json();
      toast({
        title: 'Tip Submitted',
        description: `Anonymous tip submitted successfully. Reference ID: ${result.tip_id}`,
        status: 'success',
        duration: 5000,
        isClosable: true
      });

      setShowAnonymousTipModal(false);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to submit anonymous tip',
        status: 'error',
        duration: 5000,
        isClosable: true
      });
    }
  };

  const EducationalModal = () => (
    <Modal isOpen={showEducation} onClose={() => setShowEducation(false)} size="xl">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>Security Analysis & Tips</ModalHeader>
        <ModalCloseButton />
        <ModalBody pb={6}>
          <VStack spacing={4} align="stretch">
            {educationalContent.length > 0 && (
              <Box>
                <Heading size="sm" mb={2}>Detected Indicators</Heading>
                <List spacing={3}>
                  {educationalContent.map((indicator, index) => (
                    <ListItem key={index}>
                      <HStack>
                        <ListIcon 
                          as={indicator.severity === 'high' ? FaExclamationCircle : FaShieldVirus} 
                          color={indicator.severity === 'high' ? 'red.500' : 'orange.500'} 
                        />
                        <VStack align="start" spacing={1}>
                          <Text fontWeight="bold">{indicator.type}</Text>
                          <Text fontSize="sm">{indicator.description}</Text>
                          <Text fontSize="sm" color="blue.600">
                            Tip: {indicator.educationalTip}
                          </Text>
                        </VStack>
                      </HStack>
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}

            <Accordion allowMultiple>
              <AccordionItem>
                <AccordionButton>
                  <Box flex="1" textAlign="left">
                    <HStack>
                      <Icon as={FaBookReader} />
                      <Text fontWeight="bold">Security Best Practices</Text>
                    </HStack>
                  </Box>
                  <AccordionIcon />
                </AccordionButton>
                <AccordionPanel pb={4}>
                  <List spacing={3}>
                    {SECURITY_TIPS.map((tip, index) => (
                      <ListItem key={index}>
                        <HStack>
                          <ListIcon as={FaCheckCircle} color="green.500" />
                          <VStack align="start" spacing={0}>
                            <Text fontWeight="bold">{tip.title}</Text>
                            <Text fontSize="sm">{tip.description}</Text>
                          </VStack>
                        </HStack>
                      </ListItem>
                    ))}
                  </List>
                </AccordionPanel>
              </AccordionItem>
            </Accordion>
          </VStack>
        </ModalBody>
      </ModalContent>
    </Modal>
  );

  const SecurityDisclaimer: React.FC = () => (
    <Alert status="info" variant="left-accent" mt={4} borderRadius="md">
      <AlertIcon />
      <Box>
        <AlertTitle>Important Security Notice</AlertTitle>
        <AlertDescription>
          <Text fontSize="sm">
            While our scanner uses multiple security databases and analysis techniques, new threats emerge constantly. 
            A "safe" result doesn't guarantee 100% safety. Always:
          </Text>
          <List spacing={2} mt={2} fontSize="sm">
            <ListItem>
              <ListIcon as={FaCheckCircle} color="green.500" />
              Double-check the URL spelling and domain
            </ListItem>
            <ListItem>
              <ListIcon as={FaCheckCircle} color="green.500" />
              Verify if the website requires sensitive information
            </ListItem>
            <ListItem>
              <ListIcon as={FaCheckCircle} color="green.500" />
              Use trusted bookmarks for important sites
            </ListItem>
            <ListItem>
              <ListIcon as={FaCheckCircle} color="green.500" />
              Report suspicious URLs even if marked safe
            </ListItem>
          </List>
        </AlertDescription>
      </Box>
    </Alert>
  );

  const BadgeModal = () => (
    <Modal isOpen={showBadgeModal} onClose={() => setShowBadgeModal(false)}>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>New Badge Earned! 🎉</ModalHeader>
        <ModalCloseButton />
        <ModalBody pb={6}>
          {newBadge && (
            <VStack spacing={4} align="center">
              <Icon as={newBadge.icon} w={16} h={16} color="yellow.400" />
              <Heading size="md">{newBadge.name}</Heading>
              <Text>{newBadge.description}</Text>
            </VStack>
          )}
        </ModalBody>
      </ModalContent>
    </Modal>
  );

  const CyberCellReportModal = () => (
    <Modal isOpen={showCyberCellModal} onClose={() => setShowCyberCellModal(false)} size="xl">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>
          <HStack spacing={2}>
            <Icon as={FaShieldAlt} color="blue.500" />
            <Text>Report to MP Cyber Cell</Text>
          </HStack>
        </ModalHeader>
        <ModalCloseButton />
        <ModalBody pb={6}>
          <VStack spacing={4}>
            <Alert status="info">
              <AlertIcon />
              <Box>
                <AlertTitle>Important Notice</AlertTitle>
                <AlertDescription>
                  This report will be sent directly to the MP Police Cyber Cell. False reporting is a punishable offense.
                </AlertDescription>
              </Box>
            </Alert>

            <FormControl>
              <FormLabel>Reporter Name (Optional)</FormLabel>
              <Input
                placeholder="Your name"
                value={reporterInfo.name}
                onChange={(e) => setReporterInfo({...reporterInfo, name: e.target.value})}
              />
            </FormControl>

            <FormControl>
              <FormLabel>Contact Information (Optional)</FormLabel>
              <Input
                placeholder="Phone or email"
                value={reporterInfo.contact}
                onChange={(e) => setReporterInfo({...reporterInfo, contact: e.target.value})}
              />
            </FormControl>

            <FormControl>
              <FormLabel>Location (Optional)</FormLabel>
              <Input
                placeholder="Your city/district"
                value={reporterInfo.location}
                onChange={(e) => setReporterInfo({...reporterInfo, location: e.target.value})}
              />
            </FormControl>

            <Button
              leftIcon={<Icon as={FaShieldAlt} />}
              colorScheme="blue"
              onClick={handleCyberCellReport}
              w="full"
            >
              Submit Report to Cyber Cell
            </Button>
          </VStack>
        </ModalBody>
      </ModalContent>
    </Modal>
  );

  const AnonymousTipModal = () => (
    <Modal isOpen={showAnonymousTipModal} onClose={() => setShowAnonymousTipModal(false)} size="xl">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>Submit Anonymous Tip</ModalHeader>
        <ModalCloseButton />
        <ModalBody pb={6}>
          <VStack spacing={4}>
            <FormControl>
              <FormLabel>Type of Threat</FormLabel>
              <Select
                value={anonymousTip.tip_type}
                onChange={(e) => setAnonymousTip({...anonymousTip, tip_type: e.target.value})}
              >
                <option value="URL">Suspicious URL</option>
                <option value="SMS">Suspicious SMS</option>
                <option value="EMAIL">Phishing Email</option>
                <option value="OTHER">Other Cyber Threat</option>
              </Select>
            </FormControl>

            <FormControl>
              <FormLabel>Threat Details</FormLabel>
              <Textarea
                placeholder="Describe the suspicious activity..."
                value={anonymousTip.content}
                onChange={(e) => setAnonymousTip({...anonymousTip, content: e.target.value})}
              />
            </FormControl>

            <FormControl>
              <FormLabel>Additional Information</FormLabel>
              <Textarea
                placeholder="Any additional details that might help..."
                value={anonymousTip.additional_details || ''}
                onChange={(e) => setAnonymousTip({...anonymousTip, additional_details: e.target.value})}
              />
            </FormControl>

            <Button
              leftIcon={<Icon as={FaUserSecret} />}
              colorScheme="purple"
              onClick={handleAnonymousTip}
              w="full"
            >
              Submit Anonymous Tip
            </Button>
          </VStack>
        </ModalBody>
      </ModalContent>
    </Modal>
  );

  const checkOfflineDB = (urlToCheck: string): boolean => {
    return offlineDB.has(urlToCheck);
  };

  const updateBadges = (reportCount: number) => {
    const newBadges = [...userBadges];
    let earned = false;

    if (reportCount === 1 && !newBadges[0].earned) {
      newBadges[0].earned = true;
      earned = true;
      setNewBadge(newBadges[0]);
    } else if (reportCount >= 5 && !newBadges[1].earned) {
      newBadges[1].earned = true;
      earned = true;
      setNewBadge(newBadges[1]);
    } else if (reportCount >= 10 && !newBadges[2].earned) {
      newBadges[2].earned = true;
      earned = true;
      setNewBadge(newBadges[2]);
    }

    if (earned) {
      setUserBadges(newBadges);
      localStorage.setItem('userBadges', JSON.stringify(newBadges));
      setShowBadgeModal(true);
    }
  };

  const getRandomTip = (): PhishingTip => {
    const index = Math.floor(Math.random() * PHISHING_TIPS.length);
    return PHISHING_TIPS[index];
  };

  useEffect(() => {
    const updateOfflineDB = async () => {
      try {
        const response = await fetch('/api/known-phishing-urls');
        if (response.ok) {
          const data = await response.json();
          setOfflineDB(new Set(data.urls));
          localStorage.setItem('offlinePhishingDB', JSON.stringify(Array.from(data.urls)));
        }
      } catch (error) {
        console.error('Failed to update offline database:', error);
      }
    };

    updateOfflineDB();
    const interval = setInterval(updateOfflineDB, 24 * 60 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const LoadingStates = () => (
    <VStack spacing={2} align="stretch" w="full">
      {isQuickScanning && (
        <Box>
          <Text fontSize="sm" color="gray.600" mb={2}>Quick Security Check...</Text>
          <Progress size="xs" isIndeterminate colorScheme="blue" />
        </Box>
      )}
      {isScanning && !isQuickScanning && (
        <Box>
          <Text fontSize="sm" color="gray.600" mb={2}>Performing Deep Scan...</Text>
          <Progress 
            size="xs" 
            isIndeterminate 
            colorScheme="primary"
          />
          <HStack justify="center" spacing={2} mt={2}>
            <Spinner size="sm" color="primary.500" />
            <Text fontSize="sm" color="gray.600">
              Analyzing security databases...
            </Text>
          </HStack>
        </Box>
      )}
    </VStack>
  );

  return (
    <Container maxW="container.md" py={8}>
      <VStack spacing={8}>
        <Box textAlign="center">
          <Box as="span">
            <Icon as={FaShieldAlt} w={12} h={12} color="primary.500" mb={4} />
          </Box>
          <Heading
            as="h1"
            size="xl"
            bgGradient="linear(to-r, primary.500, secondary.500)"
            bgClip="text"
            letterSpacing="tight"
          >
            URL Security Scanner
          </Heading>
          <Text color="gray.600" mt={2}>
            Check if a URL is safe before visiting
          </Text>
        </Box>

        <Box
          w="full"
          bg="white"
          borderRadius="xl"
          boxShadow="xl"
          p={6}
          borderWidth={1}
          borderColor="gray.100"
        >
          <VStack spacing={4}>
            <HStack w="full">
              <Input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to scan..."
                size="lg"
                borderRadius="lg"
                borderWidth={2}
                _focus={{
                  borderColor: 'primary.500',
                  boxShadow: '0 0 0 1px var(--chakra-colors-primary-500)',
                }}
                disabled={isScanning || isQuickScanning}
              />
              <Tooltip label="Enter the complete URL including http:// or https://">
                <Box as="span">
                  <Icon as={FaInfoCircle} color="gray.400" w={5} h={5} />
                </Box>
              </Tooltip>
            </HStack>

            <Button
              onClick={handleScan}
              isLoading={isScanning || isQuickScanning}
              loadingText={isQuickScanning ? "Quick Scan..." : "Deep Scan..."}
              variant="primary"
              size="lg"
              w="full"
              leftIcon={
                <Box as="span">
                  <Icon
                    as={FaShieldAlt}
                    animation={
                      (isScanning || isQuickScanning) 
                        ? `${pulseAnimation} 1.5s infinite` 
                        : 'none'
                    }
                  />
                </Box>
              }
            >
              Scan URL
            </Button>

            {(isQuickScanning || isScanning) && <LoadingStates />}

            {quickResult && !scanResult && (
              <Alert
                status={quickResult.isSuspicious ? 'warning' : 'info'}
                variant="left-accent"
              >
                <AlertIcon />
                <Box>
                  <AlertTitle>
                    {quickResult.isSuspicious 
                      ? 'Preliminary Warning' 
                      : 'Quick Check Complete'}
                  </AlertTitle>
                  <AlertDescription>
                    {quickResult.isSuspicious 
                      ? quickResult.reason 
                      : 'No immediate red flags found. Performing detailed analysis...'}
                  </AlertDescription>
                </Box>
              </Alert>
            )}
          </VStack>
        </Box>

        {scanResult && (
          <MotionBox
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            w="full"
          >
            <VStack spacing={4} w="full">
              <Alert
                status={scanResult.isSafe ? 'success' : 'error'}
                variant="subtle"
                flexDirection="column"
                alignItems="center"
                justifyContent="center"
                textAlign="center"
                borderRadius="xl"
                p={6}
              >
                <AlertIcon boxSize="40px" mr={0} />
                <AlertTitle mt={4} mb={1} fontSize="lg">
                  {scanResult.whitelisted ? 'Verified Safe Domain' : 
                   scanResult.isSafe ? 'URL Analysis Results' : 'Warning: Potential Threat Detected'}
                </AlertTitle>
                <AlertDescription maxWidth="sm">
                  <Text mb={4}>{scanResult.message}</Text>
                  
                  <VStack spacing={2} mb={4}>
                    <Badge 
                      colorScheme={
                        scanResult.whitelisted ? 'green' :
                        scanResult.confidence >= 0.8 ? 'green' : 
                        scanResult.confidence >= 0.6 ? 'yellow' : 'red'
                      }
                      p={2}
                      borderRadius="md"
                      fontSize="md"
                    >
                      Overall Safety Score: {formatConfidenceScore(scanResult.confidence)}
                    </Badge>
                    
                    <HStack spacing={4} fontSize="sm">
                      <Tooltip label="Machine Learning model confidence">
                        <Badge colorScheme="blue">
                          ML Score: {formatConfidenceScore(scanResult.mlConfidence)}
                        </Badge>
                      </Tooltip>
                      
                      <Tooltip label="VirusTotal security vendors confidence">
                        <Badge colorScheme="purple">
                          VT Score: {formatConfidenceScore(scanResult.vtConfidence)}
                        </Badge>
                      </Tooltip>
                    </HStack>
                  </VStack>

                  {scanResult.lastSeen && (
                    <Text fontSize="sm" color="gray.600" mb={4}>
                      First seen: {new Date(scanResult.lastSeen).toLocaleDateString()}
                    </Text>
                  )}

                  {scanResult.domainAge && (
                    <Text fontSize="sm" color="gray.600" mb={4}>
                      Domain age: {scanResult.domainAge}
                    </Text>
                  )}

                  {scanResult.threats.length > 0 && (
                    <VStack mt={4} spacing={2} align="start">
                      <Text fontWeight="bold">Detected Threats:</Text>
                      {scanResult.threats.map((threat, index) => (
                        <HStack key={index} color="red.600">
                          <Icon as={FaExclamationTriangle} />
                          <Text>{threat}</Text>
                        </HStack>
                      ))}
                    </VStack>
                  )}

                  <Box mt={4} p={4} bg="gray.50" borderRadius="md">
                    <Text fontWeight="bold" mb={2}>Additional Safety Checks:</Text>
                    <List spacing={2}>
                      <ListItem>
                        <HStack>
                          <Icon as={FaShieldAlt} color="blue.500" />
                          <Text fontSize="sm">Verify the domain matches the expected website</Text>
                        </HStack>
                      </ListItem>
                      <ListItem>
                        <HStack>
                          <Icon as={FaLock} color="blue.500" />
                          <Text fontSize="sm">Check for HTTPS and valid certificate</Text>
                        </HStack>
                      </ListItem>
                      <ListItem>
                        <HStack>
                          <Icon as={FaExclamationTriangle} color="blue.500" />
                          <Text fontSize="sm">Be cautious if the site requests sensitive information</Text>
                        </HStack>
                      </ListItem>
                    </List>
                  </Box>

                  <Divider my={4} />

                  <HStack spacing={4} mt={4}>
                    <Tooltip label="Copy URL">
                      <IconButton
                        aria-label="Copy URL"
                        icon={<FaCopy />}
                        onClick={handleCopy}
                        size="sm"
                        variant="ghost"
                      />
                    </Tooltip>
                    
                    <Tooltip label="Share Results">
                      <IconButton
                        aria-label="Share Results"
                        icon={<FaShare />}
                        onClick={handleShare}
                        size="sm"
                        variant="ghost"
                      />
                    </Tooltip>
                    
                    <Tooltip label="Rescan URL">
                      <IconButton
                        aria-label="Rescan URL"
                        icon={<FaRedoAlt />}
                        onClick={handleRescan}
                        size="sm"
                        variant="ghost"
                        isLoading={isScanning}
                      />
                    </Tooltip>
                    
                    <Tooltip label="View Scan History">
                      <IconButton
                        onClick={() => navigate('/history')}
                        aria-label="View History"
                        icon={<FaHistory />}
                        size="sm"
                        variant="ghost"
                      />
                    </Tooltip>

                    <Tooltip label="Report False Positive">
                      <IconButton
                        aria-label="Report False Positive"
                        icon={<FaFlag />}
                        onClick={() => setShowReportModal(true)}
                        size="sm"
                        variant="ghost"
                        colorScheme="red"
                      />
                    </Tooltip>

                    <Tooltip label="Report to MP Cyber Cell">
                      <IconButton
                        aria-label="Report to Cyber Cell"
                        icon={<FaShieldAlt />}
                        onClick={() => setShowCyberCellModal(true)}
                        size="sm"
                        variant="ghost"
                        colorScheme="blue"
                      />
                    </Tooltip>

                    <Tooltip label="Submit Anonymous Tip">
                      <IconButton
                        aria-label="Submit Anonymous Tip"
                        icon={<FaUserSecret />}
                        onClick={() => setShowAnonymousTipModal(true)}
                        size="sm"
                        variant="ghost"
                        colorScheme="purple"
                      />
                    </Tooltip>
                  </HStack>

                  <Text fontSize="sm" color="gray.500" mt={4}>
                    Scanned at: {formatScanDate(scanResult.timestamp!)}
                  </Text>
                </AlertDescription>
              </Alert>

              {currentTip && (
                <Alert status="info" variant="left-accent" borderRadius="md">
                  <AlertIcon />
                  <Box>
                    <AlertTitle>Security Tip: {currentTip.title}</AlertTitle>
                    <AlertDescription>
                      {currentTip.content}
                    </AlertDescription>
                  </Box>
                </Alert>
              )}

              <Box w="full" p={4} bg="gray.50" borderRadius="md">
                <Heading size="sm" mb={4}>Your Security Badges</Heading>
                <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
                  {userBadges.map((badge) => (
                    <VStack
                      key={badge.id}
                      p={3}
                      bg={badge.earned ? 'green.50' : 'gray.100'}
                      borderRadius="md"
                      opacity={badge.earned ? 1 : 0.6}
                    >
                      <Icon
                        as={badge.icon}
                        w={6}
                        h={6}
                        color={badge.earned ? 'green.500' : 'gray.500'}
                      />
                      <Text fontSize="sm" fontWeight="bold" textAlign="center">
                        {badge.name}
                      </Text>
                      <Text fontSize="xs" color="gray.600" textAlign="center">
                        {badge.criteria}
                      </Text>
                    </VStack>
                  ))}
                </SimpleGrid>
              </Box>

              <SecurityDisclaimer />
            </VStack>
          </MotionBox>
        )}
      </VStack>

      <Box
        as={motion.div}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        sx={floatingButtonStyles}
      >
        <IconButton
          aria-label="Report to MP Cyber Cell"
          icon={<Icon as={FaShieldAlt} w={6} h={6} />}
          onClick={() => setShowCyberCellModal(true)}
          colorScheme="blue"
          size="lg"
          isRound
          boxShadow="0 4px 12px rgba(0,0,0,0.1)"
          _hover={{
            boxShadow: '0 6px 16px rgba(0,0,0,0.15)',
          }}
        />
      </Box>

      <EducationalModal />
      <BadgeModal />
      <CyberCellReportModal />
      <AnonymousTipModal />
    </Container>
  );
};

const ThreatDetails: React.FC<{ result: ScanResult }> = ({ result }) => {
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'red.500';
      case 'high':
        return 'orange.500';
      case 'medium':
        return 'yellow.500';
      case 'low':
        return 'green.500';
      default:
        return 'gray.500';
    }
  };

  return (
    <VStack spacing={4} align="stretch" w="100%">
      <Box>
        <Heading size="md" mb={2}>Threat Analysis</Heading>
        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
          <Box p={4} borderRadius="md" borderWidth="1px">
            <Heading size="sm" mb={2}>ML Model Confidence</Heading>
            <Progress
              value={result.mlConfidence * 100}
              colorScheme={result.mlConfidence > 0.8 ? "red" : result.mlConfidence > 0.5 ? "yellow" : "green"}
              size="lg"
              borderRadius="md"
            />
            <Text mt={2} fontSize="sm">
              {(result.mlConfidence * 100).toFixed(1)}% confidence in prediction
            </Text>
          </Box>
          <Box p={4} borderRadius="md" borderWidth="1px">
            <Heading size="sm" mb={2}>Detection Summary</Heading>
            <SimpleGrid columns={2} spacing={2}>
              <Text>Phishing:</Text>
              <Text>{result.detectionCount.phishing}</Text>
              <Text>Malware:</Text>
              <Text>{result.detectionCount.malware}</Text>
              <Text>Suspicious:</Text>
              <Text>{result.detectionCount.suspicious}</Text>
              <Text>Malicious:</Text>
              <Text>{result.detectionCount.malicious}</Text>
            </SimpleGrid>
          </Box>
        </SimpleGrid>
      </Box>

      <Box>
        <Heading size="md" mb={2}>Detected Threats</Heading>
        <List spacing={2}>
          {result.threats.map((threat, index) => (
            <ListItem key={index} display="flex" alignItems="center">
              <ListIcon
                as={threat.startsWith('ML Model:') ? FaRobot : FaExclamationTriangle}
                color={threat.startsWith('ML Model:') ? 'blue.500' : 'red.500'}
              />
              <Text>{threat}</Text>
            </ListItem>
          ))}
        </List>
      </Box>

      <Box>
        <Heading size="md" mb={2}>Categories</Heading>
        <Wrap>
          {result.categories.map((category, index) => (
            <WrapItem key={index}>
              <Badge
                colorScheme={category === 'phishing' ? 'red' : category === 'malware' ? 'orange' : 'yellow'}
                p={2}
                borderRadius="md"
              >
                {category}
              </Badge>
            </WrapItem>
          ))}
        </Wrap>
      </Box>
    </VStack>
  );
}; 