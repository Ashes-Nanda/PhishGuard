import { Request, Response, NextFunction } from 'express';
import { collections } from '../config/firebase';

const WINDOW_SIZE = 60 * 1000; // 1 minute
const MAX_REQUESTS = 10; // 10 requests per minute

export const rateLimiter = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ip = req.ip;
    const now = Date.now();
    const windowStart = now - WINDOW_SIZE;

    // Get requests in the current window
    const requestsSnapshot = await collections.scanHistory
      .where('ip', '==', ip)
      .where('timestamp', '>=', new Date(windowStart))
      .get();

    if (requestsSnapshot.size >= MAX_REQUESTS) {
      return res.status(429).json({
        error: 'Too many requests',
        message: 'Please wait before making more requests'
      });
    }

    next();
  } catch (error) {
    console.error('Rate limiter error:', error);
    next(); // Continue on error
  }
}; 