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
            bgGradient="linear(to-r, primary.500, secondary.500)"
            bgClip="text"
          >
            Scan History
          </Heading>
          <Text color="gray.600" mt={2}>
            View your previous URL scan results
          </Text>
        </Box>

        {history.length === 0 ? (
          <Box textAlign="center" py={10}>
            <Text color="gray.500">No scan history available</Text>
          </Box>
        ) : (
          <Box overflowX="auto">
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>URL</Th>
                  <Th>Status</Th>
                  <Th>Scanned At</Th>
                  <Th>Message</Th>
                  <Th>Actions</Th>
                </Tr>
              </Thead>
              <Tbody>
                {history.map((item) => (
                  <Tr key={item.timestamp}>
                    <Td maxW="300px" isTruncated>
                      <Tooltip label={item.url}>
                        <Text>{item.url}</Text>
                      </Tooltip>
                    </Td>
                    <Td>
                      <Badge
                        colorScheme={item.isSafe ? 'green' : 'red'}
                        borderRadius="full"
                        px={2}
                      >
                        {item.isSafe ? 'Safe' : 'Unsafe'}
                      </Badge>
                    </Td>
                    <Td>{new Date(item.timestamp).toLocaleString()}</Td>
                    <Td maxW="200px" isTruncated>
                      <Tooltip label={item.message}>
                        <Text>{item.message}</Text>
                      </Tooltip>
                    </Td>
                    <Td>
                      <IconButton
                        aria-label="Delete scan"
                        icon={<FaTrash />}
                        size="sm"
                        colorScheme="red"
                        variant="ghost"
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