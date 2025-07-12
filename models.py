from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    location = db.Column(db.String(150))
    photo = db.Column(db.String(300))
    skills_offered = db.Column(db.String(300))
    skills_wanted = db.Column(db.String(300))
    availability = db.Column(db.String(100))
    is_public = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    banned = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(150), nullable=False)

    @property
    def avatar_color(self):
        # Deterministic color based on name
        return f'{abs(hash(self.name)) % 0xFFFFFF:06x}'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.name}>'

class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    skill_offered = db.Column(db.String(150))
    skill_wanted = db.Column(db.String(150))
    message = db.Column(db.String(500))  # Message from requester
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Relationships
    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])
    feedbacks = db.relationship('Feedback', backref='swap', lazy='dynamic')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    swap_id = db.Column(db.Integer, db.ForeignKey('swap_request.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rating = db.Column(db.Integer)
    review = db.Column(db.String(500))  # Changed from comment to review
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Ensure a user can only give one feedback per swap
    __table_args__ = (db.UniqueConstraint('swap_id', 'user_id', name='_swap_user_uc'),)
    
    # Relationships
    user = db.relationship('User', backref='feedbacks')

class AdminMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, default=None)  # Make nullable with default
    message = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Relationship
    user = db.relationship('User', backref='admin_messages')

class UserMessage(db.Model):
    __tablename__ = 'user_message'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy=True))

    def __repr__(self):
        return f'<UserMessage {self.id} from {self.sender_id} to {self.recipient_id}>'

def init_db(app):
    with app.app_context():
        db.create_all()
