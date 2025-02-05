require('dotenv').config();
const admin = require('firebase-admin');

const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

const db = admin.firestore();
const collections = {
  scanHistory: db.collection('scan_history')
};

async function testFirebaseConnection() {
    try {
        console.log('Testing Firebase connection...');
        
        // Test write operation
        const testDoc = await collections.scanHistory.add({
            test: true,
            timestamp: new Date(),
            message: 'Test connection successful'
        });
        console.log('Write test successful, document ID:', testDoc.id);
        
        // Test read operation
        const docData = await testDoc.get();
        console.log('Read test successful, data:', docData.data());
        
        // Clean up - delete test document
        await testDoc.delete();
        console.log('Delete test successful');
        
        console.log('All Firebase operations completed successfully! ✅');
    } catch (error) {
        console.error('Firebase test failed:', error);
        process.exit(1);
    }
}

testFirebaseConnection().then(() => process.exit(0)); 