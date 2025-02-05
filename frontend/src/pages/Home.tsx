import React from 'react';
import { URLScanner } from '../components/URLScanner';
import { motion } from 'framer-motion';

const Home: React.FC = () => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <URLScanner />
    </motion.div>
  );
};

export default Home; 