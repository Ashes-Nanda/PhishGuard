import React from 'react'
import {
  Container,
  VStack,
  Heading,
  Text,
  SimpleGrid,
  Icon,
  List,
  ListItem,
  ListIcon,
  useColorMode,
  useColorModeValue,
  Box,
} from '@chakra-ui/react'
import {
  FaShieldAlt,
  FaSearch,
  FaDatabase,
  FaBrain,
  FaCheck,
  FaHistory,
} from 'react-icons/fa'
import { motion } from 'framer-motion'
import { MotionBox, pageVariants, containerVariants, itemVariants, cardVariants } from '../components/MotionBox'

interface FeatureProps {
  title: string
  icon: React.ComponentType
  children: React.ReactNode
  index: number
}

const Feature: React.FC<FeatureProps> = ({ title, icon, children, index }) => {
  const { colorMode } = useColorMode()
  
  return (
    <MotionBox
      variants={itemVariants}
      custom={index}
      whileHover="hover"
      whileTap="tap"
      bg={colorMode === 'dark' ? 'rgba(17, 25, 40, 0.75)' : 'rgba(255, 255, 255, 0.75)'}
      backdropFilter="blur(10px)"
      p={6}
      borderRadius="lg"
      border="1px solid"
      borderColor={colorMode === 'dark' ? 'rgba(255, 255, 255, 0.125)' : 'rgba(255, 255, 255, 0.75)'}
    >
      <motion.div
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ delay: index * 0.1, type: "spring", stiffness: 200 }}
      >
        <Icon as={icon} w={10} h={10} color="brand.500" mb={4} />
      </motion.div>
      <Heading size="md" mb={2} color={colorMode === 'dark' ? 'white' : 'gray.800'}>
        {title}
      </Heading>
      <Text color={colorMode === 'dark' ? 'gray.300' : 'gray.600'}>{children}</Text>
    </MotionBox>
  )
}

const About: React.FC = () => {
  const { colorMode } = useColorMode()
  const cardBg = useColorModeValue('white', 'gray.800')

  const features = [
    {
      icon: FaShieldAlt,
      title: 'URL Protection',
      description: 'Advanced security scanning to detect malicious URLs and potential threats.',
    },
    {
      icon: FaSearch,
      title: 'Real-time Scanning',
      description: 'Instant analysis of URLs using multiple security databases and algorithms.',
    },
    {
      icon: FaHistory,
      title: 'Scan History',
      description: 'Keep track of your URL scans and maintain a history of security checks.',
    },
  ]

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <Container maxW="container.lg" py={10}>
        <VStack spacing={10}>
          <Box textAlign="center">
            <Heading
              bgGradient="linear(to-r, primary.500, secondary.500)"
              bgClip="text"
              fontSize={{ base: '3xl', md: '4xl' }}
              fontWeight="bold"
            >
              About URL Guardian
            </Heading>
            <Text mt={4} color="gray.600" fontSize="lg">
              Your first line of defense against malicious URLs
            </Text>
          </Box>

          <SimpleGrid columns={{ base: 1, md: 3 }} spacing={8} w="full">
            {features.map((feature, index) => (
              <Box
                key={index}
                bg={cardBg}
                p={6}
                borderRadius="xl"
                boxShadow="xl"
                textAlign="center"
              >
                <Icon as={feature.icon} w={10} h={10} color="primary.500" mb={4} />
                <Heading size="md" mb={2}>
                  {feature.title}
                </Heading>
                <Text color="gray.600">{feature.description}</Text>
              </Box>
            ))}
          </SimpleGrid>
        </VStack>
      </Container>
    </motion.div>
  )
}

export default About 