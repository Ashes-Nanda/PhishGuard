import React from 'react'
import { ChakraProvider, ColorModeScript, Box } from '@chakra-ui/react'
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { theme } from './theme'
import Navbar from './components/Navbar'
import Home from './pages/Home'
import History from './pages/History'
import About from './pages/About'
import { URLScanner } from './components/URLScanner'
import SecurityGuide from './pages/SecurityGuide'

// Wrap routes with AnimatePresence for page transitions
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
      <ColorModeScript initialColorMode={theme.config.initialColorMode} />
      <Box
        minH="100vh"
        bgGradient="linear(to-br, blue.50, purple.50)"
        backgroundAttachment="fixed"
      >
        <Router>
          <Navbar />
          <AnimatedRoutes />
        </Router>
      </Box>
    </ChakraProvider>
  )
}

export default App 