from firebase_admin import firestore
from typing import Optional, Dict, Any

class FirebaseManager:
    def __init__(self):
        self.db = firestore.client()
    
    async def save_scan_result(self, url: str, result: Dict[str, Any], user_id: Optional[str] = None) -> str:
        """
        Save a URL scan result to Firestore
        """
        collection = self.db.collection('scan_results')
        data = {
            'url': url,
            'result': result,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'user_id': user_id
        }
        doc_ref = collection.add(data)
        return doc_ref[1].id
    
    async def get_scan_history(self, user_id: Optional[str] = None, limit: int = 10):
        """
        Retrieve scan history for a user
        """
        collection = self.db.collection('scan_results')
        if user_id:
            query = collection.where('user_id', '==', user_id)
        else:
            query = collection
        
        docs = query.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit).stream()
        return [doc.to_dict() for doc in docs]
    
    async def get_scan_result(self, scan_id: str):
        """
        Retrieve a specific scan result
        """
        doc_ref = self.db.collection('scan_results').document(scan_id)
        doc = doc_ref.get()
        return doc.to_dict() if doc.exists else None

# Create a singleton instance
firebase_manager = FirebaseManager() 