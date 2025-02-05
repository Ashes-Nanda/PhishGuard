import React from 'react';
import {
  Box,
  Container,
  Heading,
  VStack,
  Text,
  Badge,
  Icon,
  SimpleGrid,
  useColorModeValue,
} from '@chakra-ui/react';
import { motion } from 'framer-motion';
import { FaCheckCircle, FaTimesCircle, FaHistory } from 'react-icons/fa';

const MotionBox = motion(Box);

interface ScanHistoryItem {
  url: string;
  timestamp: string;
  isSafe: boolean;
  threats: string[];
  message: string;
}

interface ScanHistoryProps {
  history: ScanHistoryItem[];
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ history }) => {
  const cardBg = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.700');

  return (
    <Container maxW="container.lg" py={8}>
      <VStack spacing={8} align="stretch">
        <Box textAlign="center">
          <Icon as={FaHistory} w={12} h={12} color="accent.blue" mb={4} />
          <Heading
            size="xl"
            bgGradient="linear(to-r, accent.blue, primary.500)"
            bgClip="text"
          >
            Scan History
          </Heading>
          <Text color="gray.600" mt={2}>
            Review your previous URL scans
          </Text>
        </Box>

        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
          {history.map((item, index) => (
            <MotionBox
              key={index}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <Box
                p={6}
                bg={cardBg}
                borderRadius="xl"
                borderWidth={1}
                borderColor={borderColor}
                boxShadow="lg"
                position="relative"
                overflow="hidden"
              >
                <Box
                  position="absolute"
                  top={0}
                  right={0}
                  p={4}
                >
                  <Badge
                    colorScheme={item.isSafe ? 'green' : 'red'}
                    fontSize="sm"
                    px={3}
                    py={1}
                    borderRadius="full"
                  >
                    {item.isSafe ? 'Safe' : 'Unsafe'}
                  </Badge>
                </Box>

                <VStack align="stretch" spacing={3}>
                  <Box>
                    <Text
                      fontSize="sm"
                      color="gray.500"
                      mb={1}
                    >
                      {new Date(item.timestamp).toLocaleString()}
                    </Text>
                    <Text
                      fontSize="md"
                      fontWeight="medium"
                      noOfLines={1}
                    >
                      {item.url}
                    </Text>
                  </Box>

                  <Box>
                    <Text
                      fontSize="sm"
                      color={item.isSafe ? 'green.500' : 'red.500'}
                      display="flex"
                      alignItems="center"
                    >
                      <Icon
                        as={item.isSafe ? FaCheckCircle : FaTimesCircle}
                        mr={2}
                      />
                      {item.message}
                    </Text>
                  </Box>

                  {!item.isSafe && item.threats.length > 0 && (
                    <Box>
                      <Text
                        fontSize="sm"
                        fontWeight="medium"
                        color="gray.600"
                        mb={1}
                      >
                        Detected Threats:
                      </Text>
                      <VStack
                        align="stretch"
                        spacing={1}
                        fontSize="sm"
                        color="red.600"
                      >
                        {item.threats.map((threat, idx) => (
                          <Text key={idx}>• {threat}</Text>
                        ))}
                      </VStack>
                    </Box>
                  )}
                </VStack>
              </Box>
            </MotionBox>
          ))}
        </SimpleGrid>

        {history.length === 0 && (
          <Box
            textAlign="center"
            p={8}
            bg={cardBg}
            borderRadius="xl"
            borderWidth={1}
            borderColor={borderColor}
          >
            <Text color="gray.500">No scan history available</Text>
          </Box>
        )}
      </VStack>
    </Container>
  );
}; 