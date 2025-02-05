# PhishGuard - Real-time Phishing Link Detector

PhishGuard is a real-time phishing link detection system built for the Cyber Safety Hackathon 2025. It combines machine learning and heuristic analysis to identify potentially malicious URLs and protect users from phishing attacks.

## Features

- Real-time URL analysis
- Machine learning-based threat detection
- Detailed analysis reports
- URL scanning history with real-time updates
- Modern, responsive user interface
- User authentication and personalized history
- Real-time threat notifications

## Tech Stack

- **Backend**: FastAPI (Python)
- **Frontend**: React + Vite with Chakra UI
- **Database**: Firebase Realtime Database/Firestore
- **Authentication**: Firebase Auth
- **ML/Analysis**: scikit-learn, beautifulsoup4, pandas
- **Hosting**: Firebase Hosting (frontend), Cloud Run/Vercel (backend)

## Getting Started

### Firebase Setup

1. Create a new Firebase project at [Firebase Console](https://console.firebase.google.com)
2. Enable Authentication, Firestore/Realtime Database
3. Download your Firebase service account key and save it as `firebase-credentials.json` in the project root
4. Add Firebase configuration to frontend environment variables

### Backend Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
# Create .env file
FIREBASE_CREDENTIALS_PATH=./firebase-credentials.json
```

4. Start the backend server:
```bash
uvicorn app.main:app --reload
```

### Frontend Setup

1. Install Node.js dependencies:
```bash
cd frontend
npm install
```

2. Set up Firebase configuration:
```bash
# Create .env.local file
VITE_FIREBASE_API_KEY=your_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_auth_domain
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_storage_bucket
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

3. Start the development server:
```bash
npm run dev
```

## Project Structure

```
phishguard/
├── app/                    # Backend application
│   ├── main.py            # FastAPI application
│   ├── firebase/          # Firebase configuration
│   ├── models/            # Data models
│   ├── schemas/           # Pydantic schemas
│   └── services/          # Business logic
├── frontend/              # React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── firebase/      # Firebase config & hooks
│   │   ├── pages/         # Page components
│   │   └── utils/         # Utility functions
│   └── package.json
├── tests/                 # Test files
├── firebase-credentials.json  # Firebase service account (git-ignored)
├── .env                   # Environment variables (git-ignored)
├── requirements.txt       # Python dependencies
└── README.md
```

## Key Firebase Features Used

- **Firestore/Realtime Database**: Store URL scan history and results
- **Authentication**: User management and secure access
- **Cloud Functions** (optional): Background tasks and notifications
- **Hosting**: Deploy frontend application

## Contributing

This is a solo project for the Cyber Safety Hackathon 2025. Feel free to fork and modify for your own use.

## License

MIT License 