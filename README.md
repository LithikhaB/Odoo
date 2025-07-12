# Skill Swap Platform

A simple mini application that enables users to list their skills and request others in return.

## Features
- User registration/login
- List offered and wanted skills
- Set availability and profile visibility
- Browse/search users by skill
- Request, accept, reject, or delete skill swaps
- Leave feedback after swaps
- Admin dashboard for moderation, banning, messaging, and reports

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Initialize the database:
   ```bash
   python
   >>> from app import db
   >>> db.create_all()
   >>> exit()
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Access the app at [http://localhost:5000](http://localhost:5000)

## Admin Access
- To make a user admin, set `is_admin=True` in the database for that user.

## Notes
- Profile photos are stored as URLs for simplicity.
- SQLite is used for storage.
- This is a minimal prototype. For production, add email verification, security, and robust validation.
