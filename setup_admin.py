from app import app, db, User

with app.app_context():
    user = User.query.first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f'User {user.name} has been promoted to admin.')
    else:
        print('No users found in the database.')