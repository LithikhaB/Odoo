from app import app, db
from models import User, SwapRequest, Feedback, AdminMessage, UserMessage

def create_admin():
    with app.app_context():
        # Check if admin user exists
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                name='Admin User',
                is_admin=True,
                is_public=True
            )
            admin.set_password('admin123')  # Change this in production
            db.session.add(admin)
            db.session.commit()
            print("Admin user created")
        else:
            print("Admin user already exists")

def create_sample_data():
    with app.app_context():
        # Create sample users
        user1 = User(
            email='user1@example.com',
            name='User One',
            skills_offered='Python, SQL',
            skills_wanted='JavaScript, HTML'
        )
        user1.set_password('password123')
        
        user2 = User(
            email='user2@example.com',
            name='User Two',
            skills_offered='JavaScript, HTML',
            skills_wanted='Python, SQL'
        )
        user2.set_password('password123')
        
        db.session.add_all([user1, user2])
        db.session.commit()
        
        # Create sample messages
        message1 = UserMessage(
            sender_id=user1.id,
            recipient_id=user2.id,
            content='Hi! I see you want to learn Python. I can help you with that!',
            read=False
        )
        
        message2 = UserMessage(
            sender_id=user2.id,
            recipient_id=user1.id,
            content='That would be great! When can we start?',
            read=False
        )
        
        db.session.add_all([message1, message2])
        db.session.commit()
        print("Sample data created")

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created")
        
        # Create admin user
        create_admin()
        
        # Create sample data
        create_sample_data()
        print("Database initialization complete!")
