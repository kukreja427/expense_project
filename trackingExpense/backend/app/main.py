from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from pymongo import MongoClient
from bson import ObjectId
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Query

# Initialize FastAPI app
app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection settings
MONGO_URL = "mongodb+srv://kajalkk2209:oRpqjnFdRqRxfUYa@cluster0.olgk3un.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DATABASE = "expense_tracker_db"
COLLECTION_USERS = "users"
COLLECTION_EXPENSES = "expenses"

# MongoDB client and collections
client = MongoClient(MONGO_URL)
db = client[DATABASE]
users_collection = db[COLLECTION_USERS]
expenses_collection = db[COLLECTION_EXPENSES]

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models

class User(BaseModel):
    id: Optional[str]
    username: str
    email: EmailStr
    new_balance: float = 0.0
    expenses: List[dict] = []
    transactions: List[dict] = []

    class Config:
        orm_mode = True

class UserInDB(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    new_balance: float = 0.0
    expenses: List[dict] = []
    transactions: List[dict] = []

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    new_balance: float = 0.0
    expenses: List[dict] = []
    transactions: List[dict] = []

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class Expense(BaseModel):
    id: Optional[str] = None  # Make id optional
    name: str
    category: str
    amount: float
    date: datetime
    description: Optional[str] = None  # Make description optional

# Helper functions

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else None
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency function to get current user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    print(token)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = users_collection.find_one({"email": email})

    if user is None:
        raise credentials_exception

    return UserInDB(**user)

# Routes

@app.post("/register", response_model=User)
async def register(user: UserCreate):
    # Hash the password before storing it
    hashed_password = get_password_hash(user.password)

    # Prepare user dictionary to insert into MongoDB
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]

    # Insert user into MongoDB
    user_id = users_collection.insert_one(user_dict).inserted_id

    # Fetch the user data back from MongoDB
    user_data = users_collection.find_one({"_id": user_id})

    # Construct the User object to return
    user = User(
        id=str(user_data["_id"]),
        username=user_data["username"],
        email=user_data["email"],
        new_balance= 0,  # Provide default values or fetch from user_data if available
        expenses=[],  # Provide default values or fetch from user_data if available
        transactions=[],  # Provide default values or fetch from user_data if available
    )

    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = users_collection.find_one({"email": form_data.username})
    if not user_dict:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")
    user = UserInDB(**user_dict)
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"email": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}



@app.post("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    print(current_user)
    user_data = users_collection.find_one({"email": current_user.email})

    if user_data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user = User(
        id=str(user_data["_id"]),
        username=user_data["username"],
        email=user_data["email"],
        new_balance=user_data.get("new_balance", 0),
        expenses=user_data.get("expenses", []),
        transactions=user_data.get("transactions", [])
    )

    return user

@app.post("/expenses", response_model=Expense)
async def create_expense(expense: Expense, current_user: UserInDB = Depends(get_current_user)):
    expense_dict = expense.dict()
    expense_dict["date"] = datetime.utcnow()  # Assign the current date/time

    # Remove optional fields if they are not provided
    if "id" in expense_dict and expense_dict["id"] is None:
        del expense_dict["id"]
    if "description" in expense_dict and expense_dict["description"] is None:
        del expense_dict["description"]

    # Update the user document in MongoDB to append the new expense and reduce balance
    result = users_collection.update_one(
        {"email": current_user.email},
        {
            "$push": {"expenses": expense_dict},
            "$inc": {"new_balance": -expense.amount}  # Reduce balance by expense amount
        }
    )

    if result.modified_count == 1:
        expense_id = str(result.upserted_id) if result.upserted_id else expense_dict.get("id")
        expense.id = expense_id
        return expense
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create expense")
@app.get("/expenses", response_model=List[Expense])
async def read_expenses(skip: int = 0, limit: int = 10, current_user: UserInDB = Depends(get_current_user)):
    expenses = list(expenses_collection.find({"username": current_user.username}).skip(skip).limit(limit))
    for expense in expenses:
        expense["id"] = str(expense["_id"])
    return expenses

@app.get("/expenses/{expense_id}", response_model=Expense)
async def read_expense(expense_id: str, current_user: UserInDB = Depends(get_current_user)):
    expense = expenses_collection.find_one({"_id": ObjectId(expense_id), "username": current_user.username})
    if expense is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Expense not found")
    expense["id"] = str(expense["_id"])
    return expense

@app.post("/users/balance", response_model=User)
async def update_balance(amount: float = Query(..., description="Amount to add to balance", alias="query"), current_user: UserInDB = Depends(get_current_user)):
    # Convert new_balance to float if it's stored as a string
    try:
        current_user.new_balance = float(current_user.new_balance)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid balance format")

    # Use $inc to increment the balance
    result = users_collection.update_one(
        {"email": current_user.email},
        {"$inc": {"new_balance": amount}}  # Increment the balance
    )

    if result.modified_count == 1:
        current_user.new_balance += amount
        return current_user
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update balance")
# Run the application with Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
