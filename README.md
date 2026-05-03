# SecureShield

SecureShield is a Python Flask-based Role-Based Access Control (RBAC) API.  
The project demonstrates secure authentication using JWT tokens, password hashing with bcrypt, role-based authorization, token revocation, and defensive security logging.

## Project Objective

The goal of this project is to simulate a secure backend system where users can register, log in, and access routes depending on their role.

The system supports two roles:

- User
- Admin

A normal User can access their profile, but only an Admin can delete users.

## Features

- User registration
- Secure password hashing using bcrypt
- JWT token generation during login
- Protected routes using token validation
- Role-based access control
- Admin-only delete route
- Logout using JWT token blacklisting
- Unauthorized access logging in `security.log`

## Technologies Used

- Python
- Flask
- PyJWT
- Flask-Bcrypt
- SQLite
- PowerShell for API testing

## Project Structure

```txt
SecureShield/
│
├── app.py
├── requirements.txt
├── report.md
├── security.log
└── README.md
