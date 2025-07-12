from flask_sqlalchemy import SQLAlchemy
from app import app
from models import db, AdminMessage, User
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, text

def upgrade():
    # Add email column to User table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE user ADD COLUMN email TEXT')
        conn.execute('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
        conn.execute('ALTER TABLE user ADD COLUMN banned BOOLEAN DEFAULT FALSE')
        conn.commit()

    # Add user_id column to admin_message table if it doesn't exist
    try:
        db.engine.execute(text("""
            ALTER TABLE admin_message
            ADD COLUMN user_id INTEGER REFERENCES user(id)
        """))
    except Exception as e:
        print(f"Column user_id might already exist: {str(e)}")
    
    # Update existing messages to set user_id to the current admin user
    admin_user = User.query.filter_by(is_admin=True).first()
    if admin_user:
        db.engine.execute(text("""
            UPDATE admin_message
            SET user_id = :user_id
            WHERE user_id IS NULL
        """), {"user_id": admin_user.id})
    
    # Create index for user_id if it doesn't exist
    try:
        db.engine.execute(text("""
            CREATE INDEX idx_admin_message_user_id ON admin_message(user_id)
        """))
    except Exception as e:
        print(f"Index might already exist: {str(e)}")
    
    db.session.commit()

def downgrade():
    # Remove email column from User table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE user DROP COLUMN email')
        conn.execute('ALTER TABLE user DROP COLUMN is_admin')
        conn.execute('ALTER TABLE user DROP COLUMN banned')
        conn.commit()

    # Remove user_id column from admin_message table
    try:
        db.engine.execute(text("""
            ALTER TABLE admin_message
            DROP COLUMN user_id
        """))
    except Exception as e:
        print(f"Error dropping column: {str(e)}")
    
    db.session.commit()

with app.app_context():
    try:
        # First try to drop all tables to start fresh
        db.drop_all()
        print("Tables dropped successfully")
    except Exception as e:
        print(f"Error dropping tables: {e}")
    
    try:
        # Create all tables with new schema
        db.create_all()
        print("Tables created successfully")
    except Exception as e:
        print(f"Error creating tables: {e}")
    
    try:
        upgrade()
        print("Migration successful!")
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        print("Attempting to rollback...")
        try:
            downgrade()
            print("Rollback successful!")
        except Exception as e:
            print(f"Rollback failed: {str(e)}")
    
    # Create indexes for better performance
    try:
        db.engine.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_feedback_swap ON feedback (swap_id);
            CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback (user_id);
            CREATE INDEX IF NOT EXISTS idx_swap_request_from_user ON swap_request (from_user_id);
            CREATE INDEX IF NOT EXISTS idx_swap_request_to_user ON swap_request (to_user_id);
        """))
        print("Indexes created successfully")
    except Exception as e:
        print(f"Error creating indexes: {e}")
    
    print("Migration completed!")
