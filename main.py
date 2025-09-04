from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import os
import logging
from Authentication.auth import create_jwt_token, get_current_user, get_db, validate_email
from Authentication.models import User
from Authentication.database import engine, Base

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

# FastAPI app with metadata
app = FastAPI(
    title="Simple Email Authentication API",
    description="A simple email-based authentication system with JWT tokens",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware (configure as needed for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Add your frontend URLs
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# -------------------------------
# Pydantic Models
# -------------------------------
class EmailLogin(BaseModel):
    email: EmailStr  # Validates email format
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # seconds
    message: str

class PredictionResponse(BaseModel):
    message: str
    user_email: str
    timestamp: str
    
class HealthResponse(BaseModel):
    status: str
    message: str

# -------------------------------
# API Endpoints
# -------------------------------

@app.get("/", response_model=HealthResponse)
async def root():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        message="Simple Email Authentication API is running"
    )

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Detailed health check"""
    return HealthResponse(
        status="healthy", 
        message="All services operational"
    )

@app.post("/login", response_model=TokenResponse)
async def login(user_data: EmailLogin, db: Session = Depends(get_db)):
    """
    Login with email only
    
    - **email**: A valid email address
    - Returns JWT token for authentication
    """
    try:
        email = user_data.email.lower().strip()  # Normalize email
        
        # Validate email format (extra validation)
        if not validate_email(email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Check if user exists, if not create one
        user = db.query(User).filter(User.email == email).first()
        is_new_user = False
        
        if not user:
            user = User(email=email)
            db.add(user)
            db.commit()
            db.refresh(user)
            is_new_user = True
            logger.info(f"New user created: {email}")
        else:
            logger.info(f"Existing user login: {email}")
        
        # Create JWT token
        token = create_jwt_token(email=email)
        
        return TokenResponse(
            access_token=token,
            message="New user created and logged in" if is_new_user else "Login successful"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.get("/predict", response_model=PredictionResponse)
async def predict(current_user: User = Depends(get_current_user)):
    """
    Protected prediction endpoint
    
    Requires valid JWT token in Authorization header.
    Returns personalized prediction for the authenticated user.
    """
    try:
        from datetime import datetime
        
        # Your prediction logic here
        # This is where you'd implement your actual ML model or business logic
        
        logger.info(f"Prediction requested by: {current_user.email}")
        
        return PredictionResponse(
            message="Prediction endpoint is running successfully",
            user_email=current_user.email,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Prediction error for user {current_user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction service temporarily unavailable"
        )

@app.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "message": "User authenticated successfully"
    }

# -------------------------------
# Error Handlers
# -------------------------------
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return {"error": "Endpoint not found"}

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return {"error": "Internal server error"}