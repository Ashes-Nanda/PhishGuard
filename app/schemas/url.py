from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any
from datetime import datetime

class URLCheckRequest(BaseModel):
    url: str
    user_id: Optional[str] = None

class URLAnalysisResult(BaseModel):
    url: str
    is_phishing: bool
    confidence_score: float
    analysis_features: Dict[str, Any]
    timestamp: datetime
    scan_id: str

class URLHistoryRequest(BaseModel):
    user_id: Optional[str] = None
    limit: int = 10 