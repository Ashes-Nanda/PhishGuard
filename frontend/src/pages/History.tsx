import React from 'react';
import {
  Box,
  Container,
  Heading,
  VStack,
  Text,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  IconButton,
  Tooltip,
  useToast,
} from '@chakra-ui/react';
import { FaTrash, FaRedo } from 'react-icons/fa';
import { URLScanner } from '../components/URLScanner';

interface ScanHistoryItem {
  url: string;
  timestamp: string;
  isSafe: boolean;
  message: string;
  severity: string;
}

const History: React.FC = () => {
  const toast = useToast();
  const [history, setHistory] = React.useState<ScanHistoryItem[]>([]);

  React.useEffect(() => {
    const loadHistory = () => {
      const savedHistory = localStorage.getItem('scanHistory');
      if (savedHistory) {
        setHistory(JSON.parse(savedHistory));
      }
    };
    loadHistory();
  }, []);

  const handleDelete = (timestamp: string) => {
    const newHistory = history.filter(item => item.timestamp !== timestamp);
    setHistory(newHistory);
    localStorage.setItem('scanHistory', JSON.stringify(newHistory));
    toast({
      title: 'Scan record deleted',
      status: 'success',
      duration: 2000,
      isClosable: true,
    });
  };

  return (
    <Container maxW="container.lg" py={8}>
      <VStack spacing={8} align="stretch">
        <Box textAlign="center">
          <Heading
          as="h1"
          size="xl"
          bgGradient="linear(to-r, primary.400, secondary.400)"
          bgClip="text"
          >
          Scan History
          </Heading>
          <Text color="whiteAlpha.800" mt={2}>
          View your previous URL scan results
          </Text>
        </Box>

        {history.length === 0 ? (
          <Box 
          textAlign="center" 
          py={10}
          bg="glassDark"
          borderRadius="xl"
          borderWidth="1px"
          borderColor="glassStroke"
          backdropFilter="blur(10px)"
          >
          <Text color="whiteAlpha.800">No scan history available</Text>
          </Box>
        ) : (
          <Box 
          overflowX="auto"
          bg="glassDark"
          borderRadius="xl"
          borderWidth="1px"
          borderColor="glassStroke"
          backdropFilter="blur(10px)"
          p={4}
          >
          <Table variant="simple">
            <Thead>
            <Tr>
              <Th color="whiteAlpha.900">URL</Th>
              <Th color="whiteAlpha.900">Status</Th>
              <Th color="whiteAlpha.900">Scanned At</Th>
              <Th color="whiteAlpha.900">Message</Th>
              <Th color="whiteAlpha.900">Actions</Th>
            </Tr>
            </Thead>
            <Tbody>
            {history.map((item) => (
              <Tr key={item.timestamp} _hover={{ bg: 'whiteAlpha.50' }}>
              <Td maxW="300px" isTruncated color="whiteAlpha.900">
                <Tooltip label={item.url}>
                <Text>{item.url}</Text>
                </Tooltip>
              </Td>
              <Td>
                <Badge
                colorScheme={item.isSafe ? 'green' : 'red'}
                borderRadius="full"
                px={2}
                bg={item.isSafe ? 'rgba(56, 161, 105, 0.1)' : 'rgba(245, 101, 101, 0.1)'}
                backdropFilter="blur(10px)"
                borderWidth="1px"
                borderColor="glassStroke"
                >
                {item.isSafe ? 'Safe' : 'Unsafe'}
                </Badge>
              </Td>
              <Td color="whiteAlpha.900">{new Date(item.timestamp).toLocaleString()}</Td>
              <Td maxW="200px" isTruncated color="whiteAlpha.900">
                <Tooltip label={item.message}>
                <Text>{item.message}</Text>
                </Tooltip>
              </Td>
              <Td>
                <IconButton
                aria-label="Delete scan"
                icon={<FaTrash />}
                size="sm"
                variant="glass"
                onClick={() => handleDelete(item.timestamp)}
                      />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </Box>
        )}
      </VStack>
    </Container>
  );
};

export default History; 