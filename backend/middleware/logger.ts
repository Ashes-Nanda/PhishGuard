import { Request, Response, NextFunction } from 'express';
import { collections } from '../config/firebase';

export const requestLogger = async (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  
  // Log request
  const requestLog = {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    timestamp: new Date(),
    body: req.method === 'POST' && req.body ? req.body : null
  };

  try {
    await collections.scanHistory.add({
      ...requestLog,
      type: 'request_log'
    });
  } catch (error) {
    console.error('Error logging request:', error);
  }

  // Capture response
  const originalSend = res.send;
  res.send = function (body) {
    const responseTime = Date.now() - start;
    
    // Log response
    collections.scanHistory.add({
      ...requestLog,
      type: 'response_log',
      statusCode: res.statusCode,
      responseTime,
      response: body || null
    }).catch(error => {
      console.error('Error logging response:', error);
    });

    return originalSend.call(this, body);
  };

  next();
}; 