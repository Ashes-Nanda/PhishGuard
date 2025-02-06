# URL Security Scanner

A comprehensive URL security scanning application that helps detect phishing and malicious URLs using machine learning and various security checks.

## Project Structure

```
Safety_Hack/
├── frontend/               # React TypeScript frontend
│   ├── src/               # Source code
│   ├── package.json       # Frontend dependencies
│   └── vite.config.ts     # Vite configuration
├── backend/               # TypeScript backend
│   ├── ml_model/         # ML model and feature extraction
│   ├── routes/           # API routes
│   ├── config/           # Configuration files
│   └── package.json      # Backend dependencies
└── README.md             # Project documentation
```

## Setup Instructions

1. Install dependencies:
   ```bash
   # Frontend
   cd frontend
   npm install

   # Backend
   cd backend
   npm install
   ```

2. Create a .env file in the root directory with required environment variables.

3. Start the development servers:
   ```bash
   # Frontend
   cd frontend
   npm run dev

   # Backend
   cd backend
   npm run dev
   ```

## Features

- Real-time URL security scanning
- Machine learning-based phishing detection
- Comprehensive security checks
- User-friendly interface with detailed reports
- History tracking of scanned URLs
- Security education resources

## Tech Stack

- Frontend: React, TypeScript, Chakra UI, Framer Motion
- Backend: Node.js, TypeScript, Express
- ML: TensorFlow.js, Feature extraction algorithms
