import * as admin from 'firebase-admin';
import * as dotenv from 'dotenv';
import { ServiceAccount } from 'firebase-admin';

dotenv.config();

const serviceAccount: Partial<ServiceAccount> = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount as ServiceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

export const db = admin.firestore();
export const auth = admin.auth();

// Collections
export const collections = {
  cyberCellReports: db.collection('cyber_cell_reports'),
  anonymousTips: db.collection('anonymous_tips'),
  scanHistory: db.collection('scan_history')
}; 