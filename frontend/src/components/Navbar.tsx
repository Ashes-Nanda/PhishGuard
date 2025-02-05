import React from 'react'
import {
  Box,
  Flex,
  HStack,
  Link,
  IconButton,
  useColorModeValue,
  useColorMode,
  Container,
  Image,
} from '@chakra-ui/react'
import { Link as RouterLink } from 'react-router-dom'
import { FaMoon, FaSun, FaShieldAlt } from 'react-icons/fa'

const Navbar: React.FC = () => {
  const { colorMode, toggleColorMode } = useColorMode()
  const bg = useColorModeValue('white', 'gray.800')
  const borderColor = useColorModeValue('gray.200', 'gray.700')

  return (
    <Box
      bg={bg}
      px={4}
      position="sticky"
      top={0}
      zIndex={100}
      borderBottom="1px"
      borderColor={borderColor}
      backdropFilter="blur(10px)"
      backgroundColor={useColorModeValue(
        'rgba(255, 255, 255, 0.8)',
        'rgba(26, 32, 44, 0.8)'
      )}
    >
      <Container maxW="container.xl">
        <Flex h={16} alignItems="center" justifyContent="space-between">
          <HStack spacing={8} alignItems="center">
            <RouterLink to="/">
              <HStack spacing={2}>
                <FaShieldAlt size="24px" color="var(--chakra-colors-primary-500)" />
                <Box
                  as="span"
                  fontSize="xl"
                  fontWeight="bold"
                  bgGradient="linear(to-r, primary.500, secondary.500)"
                  bgClip="text"
                >
                  URL Guardian
                </Box>
              </HStack>
            </RouterLink>
            <HStack as="nav" spacing={4} display={{ base: 'none', md: 'flex' }}>
              <Link
                as={RouterLink}
                to="/"
                px={2}
                py={1}
                rounded="md"
                _hover={{
                  textDecoration: 'none',
                  bg: useColorModeValue('gray.100', 'gray.700'),
                }}
              >
                Home
              </Link>
              <Link
                as={RouterLink}
                to="/history"
                px={2}
                py={1}
                rounded="md"
                _hover={{
                  textDecoration: 'none',
                  bg: useColorModeValue('gray.100', 'gray.700'),
                }}
              >
                History
              </Link>
              <Link
                as={RouterLink}
                to="/about"
                px={2}
                py={1}
                rounded="md"
                _hover={{
                  textDecoration: 'none',
                  bg: useColorModeValue('gray.100', 'gray.700'),
                }}
              >
                About
              </Link>
              <Link
                as={RouterLink}
                to="/security-guide"
                px={2}
                py={1}
                rounded="md"
                _hover={{
                  textDecoration: 'none',
                  bg: useColorModeValue('gray.100', 'gray.700'),
                }}
              >
                Security Guide
              </Link>
            </HStack>
          </HStack>

          <IconButton
            aria-label="Toggle color mode"
            icon={colorMode === 'light' ? <FaMoon /> : <FaSun />}
            onClick={toggleColorMode}
            variant="ghost"
            colorScheme="gray"
          />
        </Flex>
      </Container>
    </Box>
  )
}

export default Navbar 