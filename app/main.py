from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, firestore
import os
from dotenv import load_dotenv

from .schemas.url import URLCheckRequest, URLAnalysisResult, URLHistoryRequest
from .services.url_analyzer import url_analyzer
from .firebase.config import firebase_manager

# Load environment variables
load_dotenv()

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing link detection API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase
try:
    cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
    if not cred_path:
        raise ValueError("Firebase credentials path not found in environment variables")
    
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    # In production, you might want to handle this differently
    pass

@app.get("/")
async def root():
    return {"message": "Welcome to PhishGuard API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/analyze", response_model=URLAnalysisResult)
async def analyze_url(request: URLCheckRequest):
    """
    Analyze a URL for potential phishing indicators
    """
    try:
        # Analyze the URL
        result = await url_analyzer.analyze_url(request.url)
        
        # Save the result to Firebase
        scan_id = await firebase_manager.save_scan_result(
            request.url,
            result,
            request.user_id
        )
        
        # Add scan_id to the result
        result['scan_id'] = scan_id
        
        return URLAnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/history")
async def get_scan_history(request: URLHistoryRequest):
    """
    Retrieve scan history for a user
    """
    try:
        history = await firebase_manager.get_scan_history(
            user_id=request.user_id,
            limit=request.limit
        )
        return {"history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """
    Retrieve a specific scan result
    """
    try:
        result = await firebase_manager.get_scan_result(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Scan result not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 