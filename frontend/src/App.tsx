import React from 'react'
import { ChakraProvider, ColorModeScript, Box } from '@chakra-ui/react'
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { theme } from './theme'
import { TubelightNavbar } from './components/TubelightNavbar'
import Home from './pages/Home'
import History from './pages/History'
import About from './pages/About'
import SecurityGuide from './pages/SecurityGuide'

const AnimatedRoutes = () => {
  const location = useLocation()
  
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<Home />} />
        <Route path="/history" element={<History />} />
        <Route path="/about" element={<About />} />
        <Route path="/security-guide" element={<SecurityGuide />} />
      </Routes>
    </AnimatePresence>
  )
}

const App: React.FC = () => {
  return (
    <ChakraProvider theme={theme}>
      <ColorModeScript initialColorMode="dark" />
      <Box
        minH="100vh"
        bg="darkBg.900"
        backgroundImage="radial-gradient(circle at 50% 0%, rgba(0, 255, 169, 0.15), transparent 50%), radial-gradient(circle at 100% 0%, rgba(255, 0, 132, 0.15), transparent 50%)"
        backgroundAttachment="fixed"
        color="whiteAlpha.900"
        position="relative"
      >
        <Router>
          <Box position="relative" width="100%">
            <TubelightNavbar />
            <Box 
              pt={{ base: "6rem", md: "8rem" }}
              px={{ base: 4, md: 6 }}
              maxW="1200px"
              mx="auto"
            >
              <AnimatedRoutes />
            </Box>
          </Box>
        </Router>
      </Box>
    </ChakraProvider>
  )
}

export default App 