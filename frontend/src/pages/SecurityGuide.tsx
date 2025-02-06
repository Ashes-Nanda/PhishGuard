import React, { useState } from 'react';
import {
  Box,
  Container,
  Heading,
  VStack,
  Text,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  List,
  ListItem,
  ListIcon,
  Icon,
  SimpleGrid,
  Card,
  CardBody,
  HStack,
  Link,
  Button,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  useToast,
} from '@chakra-ui/react';
import { FaShieldAlt, FaCheckCircle, FaExclamationTriangle, FaLock, FaLink, FaCompressAlt, FaBook, FaExternalLinkAlt, FaFlag } from 'react-icons/fa';

const SECURITY_TIPS = [
  {
    title: 'Enable Two-Factor Authentication',
    description: 'Add an extra layer of security to your accounts by enabling 2FA wherever possible.'
  },
  {
    title: 'Use Strong, Unique Passwords',
    description: 'Create complex passwords and never reuse them across different accounts.'
  },
  {
    title: 'Keep Software Updated',
    description: 'Regularly update your operating system and applications to patch security vulnerabilities.'
  },
  {
    title: 'Verify Website Security',
    description: 'Look for HTTPS and valid certificates before entering sensitive information.'
  }
];

const EDUCATIONAL_RESOURCES = [
  {
    title: 'NIST Cybersecurity Framework',
    description: 'Comprehensive guide to managing cybersecurity risks',
    link: 'https://www.nist.gov/cyberframework',
    type: 'Framework'
  },
  {
    title: 'OWASP Top 10',
    description: 'Learn about the most critical web application security risks',
    link: 'https://owasp.org/www-project-top-ten/',
    type: 'Security Risks'
  },
  {
    title: 'Cybersecurity & Infrastructure Security Agency',
    description: 'Government resources for cybersecurity awareness',
    link: 'https://www.cisa.gov/cybersecurity',
    type: 'Government Resource'
  },
  {
    title: 'Have I Been Pwned',
    description: 'Check if your email has been compromised in data breaches',
    link: 'https://haveibeenpwned.com/',
    type: 'Security Tool'
  }
];

const SecurityGuide: React.FC = () => {
  const { isOpen, onOpen, onClose } = useDisclosure();
  const toast = useToast();
  const [reportForm, setReportForm] = useState({
    url: '',
    description: '',
    reporterEmail: ''
  });

  const handleReportSubmit = async () => {
    try {
      // TODO: Implement API call to backend
      const response = await fetch('/api/report-phishing', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(reportForm),
      });

      if (response.ok) {
        toast({
          title: 'Report Submitted',
          description: 'Thank you for helping keep the internet safe!',
          status: 'success',
          duration: 5000,
          isClosable: true,
        });
        onClose();
        setReportForm({ url: '', description: '', reporterEmail: '' });
      } else {
        throw new Error('Failed to submit report');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to submit report. Please try again.',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    }
  };

  const phishingTactics = [
    {
      title: 'URL Manipulation',
      description: 'Phishers often use URLs that look similar to legitimate websites.',
      examples: ['faceb00k.com', 'google.security-check.com'],
      icon: FaLink,
    },
    {
      title: 'Shortened URLs',
      description: 'Short URLs can hide malicious destinations.',
      examples: ['bit.ly/suspicious', 'tinyurl.com/hidden-threat'],
      icon: FaCompressAlt,
    },
    {
      title: 'Urgent Action Required',
      description: 'Messages that create a false sense of urgency to force quick, careless actions.',
      examples: ['Your account will be deleted in 24 hours', 'Immediate action required: Security breach'],
      icon: FaExclamationTriangle,
    },
    {
      title: 'Login Credential Phishing',
      description: 'Fake login pages that steal your username and password.',
      examples: ['Sign in to verify your account', 'Unusual activity detected - please login'],
      icon: FaLock,
    },
    {
      title: 'Financial Scams',
      description: 'Messages about money that are too good to be true or create panic.',
      examples: ['You won $1,000,000!', 'Unauthorized transaction detected'],
      icon: FaExclamationTriangle,
    },
    {
      title: 'Impersonation Attacks',
      description: 'Emails pretending to be from trusted contacts or organizations.',
      examples: ['From: ceo@company.example', 'IT Department: Urgent Update Required'],
      icon: FaShieldAlt,
    }
  ];

  return (
    <Container maxW="container.lg" py={8}>
      <VStack spacing={8} align="stretch">
        <Box textAlign="center">
            <Icon 
            as={FaShieldAlt} 
            w={16} 
            h={16} 
            color="primary.400" 
            mb={4} 
            filter="drop-shadow(0 0 8px rgba(0, 255, 169, 0.3))" 
            />
          <Heading
            as="h1"
            size="xl"
            bgGradient="linear(to-r, primary.500, secondary.500)"
            bgClip="text"
          >
            Security Guide
          </Heading>
          <Text color="gray.600" mt={2}>
            Learn how to protect yourself from phishing and online threats
          </Text>
        </Box>

        <Box textAlign="center">
          <Button
            leftIcon={
              <Icon 
              as={FaFlag} 
              color="red.400" 
              boxSize={5} 
              filter="drop-shadow(0 0 4px rgba(245, 101, 101, 0.3))" 
              />
            }
            variant="glass"
            size="lg"
            onClick={onOpen}
            mb={6}
          >
            Report Suspicious Activity
          </Button>
        </Box>

        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
          {phishingTactics.map((tactic, index) => (
            <Card 
              key={index}
              bg="glassDark"
              borderColor="glassStroke"
              backdropFilter="blur(10px)"
              boxShadow="0 8px 32px rgba(0, 0, 0, 0.3)"
              _hover={{
              transform: 'translateY(-2px)',
              boxShadow: '0 12px 48px rgba(0, 0, 0, 0.4)'
              }}
            >
              <CardBody>
              <VStack align="start" spacing={3}>
                <Icon 
                  as={tactic.icon} 
                  w={6} 
                  h={6} 
                  color="primary.400" 
                  filter="drop-shadow(0 0 4px rgba(0, 255, 169, 0.3))" 
                />
                <Heading size="md" color="whiteAlpha.900">{tactic.title}</Heading>
                <Text color="whiteAlpha.800">{tactic.description}</Text>
                <List spacing={2}>
                {tactic.examples.map((example, i) => (
                  <ListItem key={i} color="whiteAlpha.800">
                  <ListIcon as={FaExclamationTriangle} color="orange.400" />
                  {example}
                  </ListItem>
                    ))}
                  </List>
                </VStack>
              </CardBody>
            </Card>
          ))}
        </SimpleGrid>

        <Accordion allowMultiple>
            <AccordionItem
            border="1px solid"
            borderColor="glassStroke"
            bg="glassDark"
            borderRadius="xl"
            mb={4}
            >
            <AccordionButton 
              _hover={{ bg: 'whiteAlpha.100' }}
              borderRadius="xl"
            >
              <Box flex="1" textAlign="left">
              <Heading size="md" color="whiteAlpha.900">Best Practices</Heading>
              </Box>
              <AccordionIcon color="whiteAlpha.900" />
            </AccordionButton>
            <AccordionPanel>
              <List spacing={4}>
              {SECURITY_TIPS.map((tip, index) => (
                <ListItem key={index}>
                <HStack>
                    <ListIcon 
                    as={FaCheckCircle} 
                    color="green.400" 
                    filter="drop-shadow(0 0 4px rgba(56, 161, 105, 0.3))" 
                    />
                  <VStack align="start" spacing={0}>
                  <Text fontWeight="bold" color="whiteAlpha.900">{tip.title}</Text>
                  <Text color="whiteAlpha.800">{tip.description}</Text>
                      </VStack>
                    </HStack>
                  </ListItem>
                ))}
              </List>
            </AccordionPanel>
          </AccordionItem>

          <AccordionItem>
            <AccordionButton>
              <Box flex="1" textAlign="left">
                <Heading size="md">Educational Resources</Heading>
              </Box>
              <AccordionIcon />
            </AccordionButton>
            <AccordionPanel>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                {EDUCATIONAL_RESOURCES.map((resource, index) => (
                  <Card key={index} variant="outline">
                    <CardBody>
                      <VStack align="start" spacing={2}>
                        <HStack>
                            <Icon 
                            as={FaBook} 
                            color="primary.400" 
                            filter="drop-shadow(0 0 4px rgba(0, 255, 169, 0.3))" 
                            />
                          <Text fontWeight="bold">{resource.title}</Text>
                        </HStack>
                        <Text fontSize="sm" color="gray.600">{resource.description}</Text>
                        <Text fontSize="xs" color="gray.500">Type: {resource.type}</Text>
                        <Link href={resource.link} isExternal>
                            <Button 
                            size="sm" 
                            rightIcon={
                              <Icon 
                              as={FaExternalLinkAlt} 
                              color="secondary.400" 
                              boxSize={4} 
                              filter="drop-shadow(0 0 4px rgba(255, 0, 132, 0.3))" 
                              />
                            } 
                            variant="outline"
                            >
                            Learn More
                          </Button>
                        </Link>
                      </VStack>
                    </CardBody>
                  </Card>
                ))}
              </SimpleGrid>
            </AccordionPanel>
          </AccordionItem>
        </Accordion>

        <Modal isOpen={isOpen} onClose={onClose} size="lg">
          <ModalOverlay />
            <ModalContent
            bg="darkBg.800"
            borderColor="glassStroke"
            backdropFilter="blur(10px)"
            >
            <ModalHeader color="whiteAlpha.900">Report Phishing Attempt</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
              <FormControl isRequired>
                <FormLabel color="whiteAlpha.900">Suspicious URL</FormLabel>
                <Input 
                placeholder="Enter the suspicious URL"
                value={reportForm.url}
                onChange={(e) => setReportForm({...reportForm, url: e.target.value})}
                bg="darkBg.700"
                borderColor="glassStroke"
                color="whiteAlpha.900"
                _hover={{ borderColor: "primary.400" }}
                _focus={{ borderColor: "primary.400", boxShadow: "0 0 0 1px var(--chakra-colors-primary-400)" }}
                  />
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>Description</FormLabel>
                  <Textarea 
                    placeholder="Describe the suspicious activity"
                    value={reportForm.description}
                    onChange={(e) => setReportForm({...reportForm, description: e.target.value})}
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>Your Email (Optional)</FormLabel>
                  <Input 
                    type="email"
                    placeholder="Enter your email for updates"
                    value={reportForm.reporterEmail}
                    onChange={(e) => setReportForm({...reportForm, reporterEmail: e.target.value})}
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
                <Button variant="glass" mr={3} onClick={onClose}>
                Cancel
                </Button>
                <Button variant="glass" colorScheme="red" onClick={handleReportSubmit}>
                Submit Report
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>
      </VStack>
    </Container>
  );
};

export default SecurityGuide; 