from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from Models.user import Staff, Token, UserInDB
from Config.DB import user_collection, conn
from schemas.user import generate_credentials,generate_HR_credentials,generate_buyer_credentials, hash_password,get_current_user,authenticate_user,create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM,pwd_context,oauth2_scheme,generate_staff_id
from bson.json_util import dumps
import pytz


user = APIRouter()

@user.post("/signup/hr")
async def signup_hr(staff: Staff, password: str):
    existing_user = user_collection.find_one({"email": staff.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    

    #generate the credentials
    firstname = staff.first_name
    lastname = staff.last_name
    username = generate_HR_credentials(firstname.upper(),lastname.upper())
    staff_id = generate_staff_id(firstname.upper(),lastname.upper())


    hashed_password = pwd_context.hash(password)
    new_user = {
        'staff_id': staff_id,
        'first_name': staff.first_name,
        'last_name': staff.last_name,
        'email': staff.email,
        'phone_number': staff.phone_number,
        'job_title': staff.job_title,
        'role': "HR",
        'username': username,
        'hashed_password': hashed_password,
        'Added_by': username,
        "Disabled" : False,
        "created_at": datetime.now(pytz.timezone('Africa/Lagos')) + timedelta(hours=1) 
    }
    user_collection.insert_one(new_user)

    return {"message": "Admin Account created successfully"}

# Add a new staff member

@user.post('/add_staff')
async def add_staff(staff: Staff, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "HR":
        return({"message": "You Are Not Authorised To Add Seller."})
    # Check if the email already exists
    existing_staff = user_collection.find_one({'email': staff.email})
    if existing_staff:
        raise HTTPException(status_code=400, detail='Staff member already exists')

    # Generate the credentials
    firstname = staff.first_name
    lastname = staff.last_name
    username, password = generate_credentials(firstname,lastname)
    hashed_password = hash_password(password)
    staff_id = generate_staff_id(firstname.upper(),lastname.upper())

    # Save the staff member to the database
    user_collection.insert_one({
        'first_name': staff.first_name,
        'last_name': staff.last_name,
        'email': staff.email,
        'staff_id': staff_id,
        'phone_number': staff.phone_number,
        'job_title': staff.job_title,
        'role': "seller",
        'username': username,
        'hashed_password': hashed_password,
        "Disabled" : False,
        "created_at": datetime.now(pytz.timezone('Africa/Lagos')) + timedelta(hours=1)
    })

    # Send the email
    # send_email(staff.email, username, password)

    return {'message': 'Staff member added successfully ' + (password)}




@user.post("/signup/buyer")
async def signup_buyer(staff: Staff, password: str):
    existing_user = user_collection.find_one({"email": staff.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    

    #generate the credentials
    firstname = staff.first_name
    lastname = staff.last_name
    username = generate_buyer_credentials(firstname.upper(),lastname.upper())
    staff_id = generate_staff_id(firstname.upper(),lastname.upper())


    hashed_password = pwd_context.hash(password)
    new_user = {
        'staff_id': staff_id,
        'first_name': staff.first_name,
        'last_name': staff.last_name,
        'email': staff.email,
        'phone_number': staff.phone_number,
        'job_title': staff.job_title,
        'role': "buyer",
        'username': username,
        'hashed_password': hashed_password,
        "Disabled" : False,
        "created_at": datetime.now(pytz.timezone('Africa/Lagos')) + timedelta(hours=1) 
    }
    user_collection.insert_one(new_user)

    return {"message": "Buyer Account created successfully"}











# @user.post("/signup/buyer")
# async def signup_buyer(staff: Staff, password: str):
#     existing_user = user_collection.find_one({"email": staff.email})
#     if existing_user:
#         raise HTTPException(status_code=400, detail="Email already registered")
    

#     #generate the credentials
#     firstname = staff.first_name
#     lastname = staff.last_name
#     username = generate_buyer_credentials(firstname.upper(),lastname.upper())
#     staff_id = generate_staff_id(firstname.upper(),lastname.upper())


#     hashed_password = pwd_context.hash(password)
#     new_user = {
#         'staff_id': staff_id,
#         'first_name': staff.first_name,
#         'last_name': staff.last_name,
#         'email': staff.email,
#         'phone_number': staff.phone_number,
#         'job_title': staff.job_title,
#         'role': "buyer",
#         'username': username,
#         'hashed_password': hashed_password,
#         "Disabled" : False,
#         "created_at": datetime.now(pytz.timezone('Africa/Lagos')) + timedelta(hours=1) 
#     }
#     user_collection.insert_one(new_user)

#     return {"message": "Buyer account created successfully"}




@user.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect Username Or Password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@user.get("/users/me/", response_model=Staff)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user

@user.get("/users/me/items")
async def read_own_items(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role == "staff":
        return [{"staff_id": current_user.staff_id, "owner": current_user}]
    elif current_user.role == "admin":
        return [{"staff_id": current_user.staff_id, "owner": current_user}]
    elif current_user.role == "HR":
        return [{"staff_id": current_user.staff_id, "owner": current_user}]
    else:
        raise HTTPException(status_code=403, detail="Forbidden")

@user.get("/hr")
async def hr(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role != "HR":
            raise HTTPException(status_code=403, detail="Forbidden")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {"message": "Welcome to the HR page"}

# Define the protected endpoint for staff
@user.get("/staff")
async def staff(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role != "staff":
            raise HTTPException(status_code=403, detail="Forbidden")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {"message": "Welcome to the staff page"}


@user.get("/hr_data")
async def get_hr_data():
    cursor = conn.find({"role": "HR"})
    data = list(cursor)  # or list(cursor.limit(1000)) to limit the number of documents
    return dumps(data)


@user.get("/staff_data")
async def get_all_staff_data():
    cursor = conn.find({"role": "staff"})
    data = list(cursor)
    return dumps(data)



from fastapi.responses import JSONResponse

@user.get("/buyer_data")
async def get_all_buyer_data():
    cursor = conn.find({"role": "buyer"})
    data = list(cursor)
    return JSONResponse(content=data, media_type="application/json")




# @user.get("/buyer_data")
# async def get_all_buyer_data():
#     cursor = conn.find({"role": "buyer"})
#     data = list(cursor)
#     return dumps(data)



@user.put("/staff/{staff_id}")
async def update_staff(staff_id: str, staff: Staff, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "HR":
        raise HTTPException(status_code=403, detail="You are not authorized to update this staff member")
    
    staff_data = user_collection.find_one({"staff_id": staff_id})
    if not staff_data:
        raise HTTPException(status_code=404, detail="Staff member not found")
    
    staff_data["firstname"] = staff.first_name
    staff_data["lastname"] = staff.last_name
    staff_data["email"] = staff.email
    # Update other staff details as needed
    
    user_collection.update_one({"staff_id": staff_id}, {"$set": staff_data})
    
    return {"message": "Staff details updated successfully"}

@user.delete("/staff/{staff_id}")
async def delete_staff(staff_id: str, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "HR":
        raise HTTPException(status_code=403, detail="You are not authorized to delete this staff member")
    
    staff_data = user_collection.find_one({"staff_id": staff_id})
    if not staff_data:
        raise HTTPException(status_code=404, detail="Staff member not found")
    
    user_collection.delete_one({"staff_id": staff_id})
    
    return {"message": "Staff member deleted successfully"}


