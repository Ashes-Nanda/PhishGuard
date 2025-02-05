import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import urlScanRoutes from './routes/urlScanRoutes';
import reportRoutes from './routes/reportRoutes';
import { rateLimiter } from './middleware/rateLimiter';
import { requestLogger } from './middleware/logger';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 8000;

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true
}));

// Add logging middleware
app.use(requestLogger);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Apply rate limiter to API routes
app.use('/api', rateLimiter);

// Routes
app.use('/api', urlScanRoutes);
app.use('/api', reportRoutes);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Health check available at: http://localhost:${port}/api/health`);
}); 