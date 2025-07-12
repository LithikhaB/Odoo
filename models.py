from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
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

class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    skill_offered = db.Column(db.String(150))
    skill_wanted = db.Column(db.String(150))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    swap_id = db.Column(db.Integer, db.ForeignKey('swap_request.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rating = db.Column(db.Integer)
    comment = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class AdminMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
