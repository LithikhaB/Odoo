from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User, SwapRequest, Feedback, AdminMessage, UserMessage, init_db
import csv
import io
from io import StringIO
from sqlalchemy.orm import aliased
from sqlalchemy import or_, and_, func
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skill_swap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)

# Initialize database tables
with app.app_context():
    init_db(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    messages = []
    if current_user.is_authenticated:
        messages = AdminMessage.query.order_by(AdminMessage.created_at.desc()).all()
    return render_template('home.html', messages=messages)

# --- User Registration ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        location = request.form.get('location')
        photo = request.form.get('photo')
        skills_offered = request.form.get('skills_offered')
        skills_wanted = request.form.get('skills_wanted')
        availability = request.form.get('availability')
        is_public = bool(request.form.get('is_public'))
        
        # Check if user exists
        if User.query.filter_by(name=name).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create user
        user = User(
            name=name,
            email=email,
            location=location,
            photo=photo,
            skills_offered=skills_offered,
            skills_wanted=skills_wanted,
            availability=availability,
            is_public=is_public
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Log in the new user
        login_user(user)
        flash('Registration successful!')
        return redirect(url_for('profile'))
    
    return render_template('register.html')

# --- User Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        try:
            # Try to find user by email or username
            user = User.query.filter((User.email == identifier) | (User.name == identifier)).first()
        except Exception:
            # Fallback to username only if email column doesn't exist
            user = User.query.filter_by(name=identifier).first()
        
        if user and user.check_password(password) and not user.banned:
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('home'))
        
        flash('Invalid identifier or password')
        return redirect(url_for('login'))
    
    return render_template('login.html')

# --- User Logout ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- User Profile ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.location = request.form.get('location')
        current_user.photo = request.form.get('photo')
        current_user.skills_offered = request.form.get('skills_offered')
        current_user.skills_wanted = request.form.get('skills_wanted')
        current_user.availability = request.form.get('availability')
        current_user.is_public = bool(request.form.get('is_public'))
        db.session.commit()
        flash('Profile updated!')
    return render_template('profile.html', user=current_user)

# --- Browse/Search Users ---
from swap_utils import get_swap_status

@app.route('/browse')
@login_required
def browse():
    q = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 6, type=int)
    users_query = User.query.filter(User.is_public==True, User.banned==False, User.id != current_user.id)
    if q:
        users_query = users_query.filter((User.skills_offered.ilike(f'%{q}%')) | (User.skills_wanted.ilike(f'%{q}%')))
    pagination = users_query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    user_statuses = {}
    user_ratings = {}
    
    for user in users:
        user_statuses[user.id] = get_swap_status(current_user.id, user.id)
        # Calculate average rating
        feedbacks = Feedback.query.join(SwapRequest).filter(
            # Get feedbacks where the user is either from_user or to_user in the swap
            (SwapRequest.from_user_id == user.id) | (SwapRequest.to_user_id == user.id),
            # AND the feedback is from a different user than the one being viewed
            Feedback.user_id != user.id
        ).all()
        if feedbacks:
            total_rating = sum(f.rating for f in feedbacks)
            user_ratings[user.id] = round(total_rating / len(feedbacks), 1)
        else:
            user_ratings[user.id] = 0
    
    return render_template('browse.html', 
        users=users, 
        pagination=pagination, 
        user_statuses=user_statuses, 
        user_ratings=user_ratings,
        q=q)

# --- Request Swap ---
@app.route('/request_swap/<int:user_id>', methods=['GET', 'POST'])
@login_required
def request_swap(user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.banned or not target_user.is_public:
        flash('User not available for swaps.')
        return redirect(url_for('browse'))
    
    if request.method == 'POST':
        message = request.form.get('message', '')
        skill_offered = request.form.get('skill_offered', '').strip()
        skill_wanted = request.form.get('skill_wanted', '').strip()
        
        if not skill_offered or not skill_wanted:
            flash('Please select both skills.')
            return redirect(url_for('browse'))
            
        swap = SwapRequest(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            skill_offered=skill_offered,
            skill_wanted=skill_wanted,
            message=message
        )
        db.session.add(swap)
        db.session.commit()
        flash('Swap request sent!')
        return redirect(url_for('browse'))
    
    # For simplicity, use first skill offered/wanted
    skill_offered = (current_user.skills_offered or '').split(',')[0].strip() if current_user.skills_offered else ''
    skill_wanted = (target_user.skills_offered or '').split(',')[0].strip() if target_user.skills_offered else ''
    return render_template('request_swap.html', target_user=target_user, 
                         skill_offered=skill_offered, skill_wanted=skill_wanted)

# --- Swap Requests (Sent/Received) ---
@app.route('/swap_requests')
@login_required
def swap_requests():
    requests = SwapRequest.query.filter_by(from_user_id=current_user.id).order_by(SwapRequest.created_at.desc()).all()
    received = SwapRequest.query.filter_by(to_user_id=current_user.id).order_by(SwapRequest.created_at.desc()).all()
    # Attach user objects for template
    for req in requests:
        req.to_user = User.query.get(req.to_user_id)
    for req in received:
        req.from_user = User.query.get(req.from_user_id)
    # Avatar color is now a property, no need to add extra logic
    return render_template('swap_requests.html', requests=requests, received=received)

@app.route('/accept_swap/<int:swap_id>')
@login_required
def accept_swap(swap_id):
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.to_user_id != current_user.id:
        flash('Unauthorized')
        return redirect(url_for('swap_requests'))
    swap.status = 'accepted'
    db.session.commit()
    flash('Swap accepted!')
    return redirect(url_for('swap_requests'))

@app.route('/reject_swap/<int:swap_id>')
@login_required
def reject_swap(swap_id):
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.to_user_id != current_user.id:
        flash('Unauthorized')
        return redirect(url_for('swap_requests'))
    swap.status = 'rejected'
    db.session.commit()
    flash('Swap rejected!')
    return redirect(url_for('swap_requests'))

@app.route('/delete_swap/<int:swap_id>')
@login_required
def delete_swap(swap_id):
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.from_user_id != current_user.id or swap.status != 'pending':
        flash('Unauthorized or already processed')
        return redirect(url_for('swap_requests'))
    swap.status = 'cancelled'
    db.session.commit()
    flash('Swap request cancelled.')
    return redirect(url_for('swap_requests'))

# --- Rate User ---
@app.route('/rate_user/<int:swap_id>', methods=['GET', 'POST'])
@login_required
def rate_user(swap_id):
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.status != 'accepted':
        flash('You can only rate completed swaps.')
        return redirect(url_for('swap_requests'))
    
    # Check if user is trying to rate themselves
    if swap.from_user_id == current_user.id and swap.to_user_id == current_user.id:
        flash('You cannot rate yourself.')
        return redirect(url_for('swap_requests'))
    
    # Check if user has already rated this swap
    existing_feedback = Feedback.query.filter_by(
        swap_id=swap_id,
        user_id=current_user.id
    ).first()
    
    if existing_feedback:
        flash('You have already rated this swap.')
        return redirect(url_for('swap_requests'))
    
    if request.method == 'POST':
        rating = int(request.form.get('rating'))
        review = request.form.get('review', '').strip()
        
        if not 1 <= rating <= 5:
            flash('Please select a rating between 1 and 5.')
            return redirect(url_for('rate_user', swap_id=swap_id))
            
        if not review:
            flash('Please provide a review.')
            return redirect(url_for('rate_user', swap_id=swap_id))
            
        feedback = Feedback(
            swap_id=swap_id,
            user_id=current_user.id,
            rating=rating,
            review=review
        )
        db.session.add(feedback)
        db.session.commit()
        flash('Thank you for your review!')
        return redirect(url_for('swap_requests'))
    
    return render_template('rate_user.html', swap=swap)

# --- Feedback ---
@app.route('/feedback/<int:swap_id>', methods=['GET', 'POST'])
@login_required
def feedback(swap_id):
    swap = SwapRequest.query.get_or_404(swap_id)
    if request.method == 'POST':
        rating = int(request.form['rating'])
        comment = request.form.get('comment')
        fb = Feedback(
            swap_id=swap_id,
            from_user_id=current_user.id,
            to_user_id=swap.to_user_id if current_user.id == swap.from_user_id else swap.from_user_id,
            rating=rating,
            comment=comment
        )
        db.session.add(fb)
        db.session.commit()
        flash('Feedback submitted!')
        return redirect(url_for('swap_requests'))
    return '''<form method="POST">
        <label>Rating (1-5):</label><input type="number" name="rating" min="1" max="5" required><br>
        <label>Comment:</label><input type="text" name="comment"><br>
        <button type="submit">Submit</button>
    </form>'''

# --- User Ratings ---
@app.route('/user_ratings/<int:user_id>')
@login_required
def user_ratings(user_id):
    user = User.query.get_or_404(user_id)
    feedbacks = Feedback.query.join(SwapRequest).filter(
        # Get feedbacks where the user is either from_user or to_user in the swap
        (SwapRequest.from_user_id == user_id) | (SwapRequest.to_user_id == user_id),
        # AND the feedback is from a different user than the one being viewed
        Feedback.user_id != user_id
    ).order_by(Feedback.created_at.desc()).all()
    
    # Calculate average rating
    if feedbacks:
        total_ratings = sum(f.rating for f in feedbacks)
        avg_rating = round(total_ratings / len(feedbacks), 1)
    else:
        avg_rating = 0
    
    return render_template('user_ratings.html', user=user, feedbacks=feedbacks, avg_rating=avg_rating)

# --- Admin Dashboard ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    # Get recent messages
    messages = AdminMessage.query.order_by(AdminMessage.created_at.desc()).limit(5).all()
    
    # Get recent swaps
    recent_swaps = SwapRequest.query.order_by(SwapRequest.created_at.desc()).limit(5).all()
    
    # Get total counts
    total_users = User.query.count()
    active_users = User.query.filter_by(is_public=True).count()
    total_swaps = SwapRequest.query.count()
    total_feedback = Feedback.query.count()
    
    return render_template('admin/dashboard.html', 
        messages=messages,
        recent_swaps=recent_swaps,
        total_users=total_users,
        active_users=active_users,
        total_swaps=total_swaps,
        total_feedback=total_feedback)

@app.route('/admin/review_skills')
@login_required
def admin_review_skills():
    if not current_user.is_admin:
        abort(403)
    
    # Get all users with their skills
    users = User.query.all()
    skills_to_review = []
    
    for user in users:
        if user.is_public:  # Only review public profiles
            skills = {
                'offered': user.skills_offered.split(',') if user.skills_offered else [],
                'wanted': user.skills_wanted.split(',') if user.skills_wanted else []
            }
            
            # Check for potential issues
            issues = []
            if skills['offered']:
                for skill in skills['offered']:
                    if skill.lower() in ['admin', 'administrator', 'moderator', 'support']:
                        issues.append(f"Suspicious skill: {skill}")
                    if len(skill) < 3:  # Too short
                        issues.append(f"Skill too short: {skill}")
                    if len(skill) > 50:  # Too long
                        issues.append(f"Skill too long: {skill}")
            
            if skills['wanted']:
                for skill in skills['wanted']:
                    if skill.lower() in ['admin', 'administrator', 'moderator', 'support']:
                        issues.append(f"Suspicious skill: {skill}")
                    if len(skill) < 3:
                        issues.append(f"Skill too short: {skill}")
                    if len(skill) > 50:
                        issues.append(f"Skill too long: {skill}")
            
            skills_to_review.append({
                'user': user,
                'skills': skills,
                'issues': issues,
                'has_issues': len(issues) > 0
            })
    
    return render_template('admin/review_skills.html', 
                         users=skills_to_review)

@app.route('/admin/approve_skill/<int:user_id>', methods=['POST'])
@login_required
def admin_approve_skill(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.is_public = True
    db.session.commit()
    flash('Skills approved successfully.', 'success')
    return redirect(url_for('admin_review_skills'))

@app.route('/admin/reject_skill/<int:user_id>', methods=['POST'])
@login_required
def admin_reject_skill(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.is_public = False
    db.session.commit()
    flash('Skills rejected successfully.', 'danger')
    return redirect(url_for('admin_review_skills'))

@app.route('/admin/ban_user/<int:user_id>')
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    user.banned = True
    db.session.commit()
    flash(f'User {user.name} has been banned.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unban_user/<int:user_id>')
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    user.banned = False
    db.session.commit()
    flash(f'User {user.name} has been unbanned.')
    return redirect(url_for('admin_review_skills'))

@app.route('/admin/monitor_swaps')
@login_required
def admin_monitor_swaps():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status = request.args.get('status', 'all')
    
    # Build query based on filters
    query = SwapRequest.query
    
    if search:
        # Search by either from_user or to_user name
        query = query.filter(
            or_(
                SwapRequest.from_user.has(User.name.ilike(f'%{search}%')),
                SwapRequest.to_user.has(User.name.ilike(f'%{search}%'))
            )
        )
    
    if status != 'all':
        query = query.filter_by(status=status)
    
    # Get paginated results
    swap_requests = query.order_by(SwapRequest.created_at.desc())\
        .paginate(page=page, per_page=10)
    
    return render_template('admin/monitor_swaps.html', 
                         swap_requests=swap_requests,
                         search=search,
                         status=status)

@app.route('/admin/send_message', methods=['GET', 'POST'])
@login_required
def admin_send_message():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        message = request.form.get('message')
        if not message:
            flash('Please enter a message.')
            return redirect(url_for('admin_send_message'))
            
        # Create admin message
        admin_msg = AdminMessage(message=message)
        db.session.add(admin_msg)
        db.session.commit()
        flash('Message sent successfully.')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/send_message.html')

@app.route('/admin/view_messages')
@login_required
def admin_view_messages():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    messages = AdminMessage.query.order_by(AdminMessage.created_at.desc()).all()
    # No need to manually get sender since we have the relationship
    return render_template('admin/view_messages.html', messages=messages)

@app.route('/admin/download_reports')
@login_required
def admin_download_reports():
    if not current_user.is_admin:
        abort(403)
    
    # Get all relevant data
    users = User.query.all()
    swaps = SwapRequest.query.all()
    feedback = Feedback.query.all()
    
    # Create CSV content
    csv_content = """User Reports:
Name,Email,Location,Skills Offered,Skills Wanted,Availability,Is Public,Is Admin,Banned
"""
    
    for user in users:
        csv_content += f"{user.name},{user.email},{user.location or 'None'},"\
                      f"{user.skills_offered or 'None'},{user.skills_wanted or 'None'},"\
                      f"{user.availability or 'None'},{user.is_public},{user.is_admin},{user.banned}\n"
    
    csv_content += "\nSwap Requests:\n"\
                   "From User,To User,Skill Offered,Skill Wanted,Message,Status,Date\n"
    
    for swap in swaps:
        csv_content += f"{swap.from_user.name},{swap.to_user.name},{swap.skill_offered or 'None'},"\
                      f"{swap.skill_wanted or 'None'},{swap.message or 'None'},"\
                      f"{swap.status},{swap.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    csv_content += "\nFeedback:\n"\
                   "User,Rating,Review,Date\n"
    
    for fb in feedback:
        csv_content += f"{fb.user.name},{fb.rating},{fb.review or 'None'},"\
                      f"{fb.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    # Create filename with current timestamp
    filename = f'skill_swap_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    # Create response
    response = make_response(csv_content)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-type"] = "text/csv"
    
    return response

@app.route('/promote_to_admin/<string:username>')
@login_required
def promote_to_admin(username):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    user = User.query.filter_by(name=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        flash(f'User {username} has been promoted to admin.')
    else:
        flash('User not found.')
    return redirect(url_for('admin_dashboard'))

@app.route('/create_first_admin')
def create_first_admin():
    # Get the first user in the database
    user = User.query.first()
    if user:
        user.is_admin = True
        db.session.commit()
        flash(f'User {user.name} has been promoted to admin.')
    else:
        flash('No users found in the database.')
    return redirect(url_for('login'))

# Initialize first admin user
@app.route('/initialize_admin')
def initialize_admin():
    # This route should only be used once to create the first admin
    admin = User.query.filter_by(name='admin').first()
    if admin:
        flash('Admin user already exists')
        return redirect(url_for('login'))
    
    # Check if there are any existing users
    if User.query.count() > 0:
        flash('Cannot initialize admin - users already exist in the database')
        return redirect(url_for('login'))
    
    # Create admin user
    admin = User(
        name='admin',
        email='admin@skillswap.com',
        is_admin=True,
        is_public=False
    )
    admin.set_password('admin123')  # Default password that should be changed
    db.session.add(admin)
    db.session.commit()
    
    flash('Admin user created successfully. Please login with username: admin and password: admin123')
    flash('Please change your password after first login.')
    return redirect(url_for('login'))

# Add admin user management routes
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/add_admin', methods=['GET', 'POST'])
@login_required
def admin_add_admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([name, email, password, confirm_password]):
            flash('Please fill in all fields.')
            return redirect(url_for('admin_add_admin'))
            
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('admin_add_admin'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('admin_add_admin'))
            
        new_admin = User(
            name=name,
            email=email,
            is_admin=True,
            is_public=False
        )
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        flash(f'Admin user {name} created successfully.')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/add_admin.html')

@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def admin_change_password():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.')
            return redirect(url_for('admin_change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match.')
            return redirect(url_for('admin_change_password'))
            
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password changed successfully.')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/change_password.html')

@app.route('/admin/approve_swap/<int:swap_id>', methods=['POST'], endpoint='admin_approve_swap')
@login_required
def admin_approve_swap(swap_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
    
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.status != 'pending':
        return jsonify({'success': False, 'message': 'Swap request is not pending'}), 400
    
    swap.status = 'accepted'
    db.session.commit()
    
    # Create feedback records for both users
    feedback1 = Feedback(
        user_id=swap.from_user_id,
        swap_id=swap_id,
        rating=0,  # Initial rating
        review='',
        created_at=datetime.utcnow()
    )
    feedback2 = Feedback(
        user_id=swap.to_user_id,
        swap_id=swap_id,
        rating=0,  # Initial rating
        review='',
        created_at=datetime.utcnow()
    )
    db.session.add_all([feedback1, feedback2])
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/reject_swap/<int:swap_id>', methods=['POST'], endpoint='admin_reject_swap')
@login_required
def admin_reject_swap(swap_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
    
    swap = SwapRequest.query.get_or_404(swap_id)
    if swap.status != 'pending':
        return jsonify({'success': False, 'message': 'Swap request is not pending'}), 400
    
    swap.status = 'rejected'
    db.session.commit()
    
    return jsonify({'success': True})

# Message Routes
@app.route('/messages')
@login_required
def messages():
    # Get all conversations using subqueries
    sent_messages = db.session.query(UserMessage).filter_by(sender_id=current_user.id)
    received_messages = db.session.query(UserMessage).filter_by(recipient_id=current_user.id)
    
    # Get users you've swapped with
    sent_swaps = db.session.query(SwapRequest).filter_by(from_user_id=current_user.id, status='accepted')
    received_swaps = db.session.query(SwapRequest).filter_by(to_user_id=current_user.id, status='accepted')
    
    # Combine both queries for messages
    all_messages = sent_messages.union(received_messages).order_by(UserMessage.created_at.desc()).all()
    
    # Build conversation list
    conversations = []
    conversation_ids = set()
    
    # Add message conversations
    for message in all_messages:
        other_user_id = message.recipient_id if message.sender_id == current_user.id else message.sender_id
        if other_user_id not in conversation_ids:
            conversation_ids.add(other_user_id)
            other_user = User.query.get(other_user_id)
            
            # Get all messages in this conversation
            conversation_messages = db.session.query(UserMessage).filter(
                ((UserMessage.sender_id == current_user.id) & (UserMessage.recipient_id == other_user_id)) |
                ((UserMessage.sender_id == other_user_id) & (UserMessage.recipient_id == current_user.id))
            ).order_by(UserMessage.created_at.asc()).all()
            
            latest_message = conversation_messages[-1] if conversation_messages else None
            unread_count = db.session.query(UserMessage).filter(
                UserMessage.recipient_id == current_user.id,
                UserMessage.sender_id == other_user_id,
                UserMessage.read == False
            ).count()
            
            conversations.append({
                'other_user': other_user,
                'last_message': latest_message,
                'messages': conversation_messages,
                'unread_count': unread_count,
                'unread': unread_count > 0,
                'type': 'message',
                'conversation_id': latest_message.id if latest_message else None
            })

    # Add swap partners
    for swap in sent_swaps.union(received_swaps).all():
        other_user_id = swap.to_user_id if swap.from_user_id == current_user.id else swap.from_user_id
        if other_user_id not in conversation_ids:
            conversation_ids.add(other_user_id)
            other_user = User.query.get(other_user_id)
            
            # Get all messages in this conversation
            conversation_messages = db.session.query(UserMessage).filter(
                ((UserMessage.sender_id == current_user.id) & (UserMessage.recipient_id == other_user_id)) |
                ((UserMessage.sender_id == other_user_id) & (UserMessage.recipient_id == current_user.id))
            ).order_by(UserMessage.created_at.asc()).all()
            
            latest_message = conversation_messages[-1] if conversation_messages else None
            unread_count = db.session.query(UserMessage).filter(
                UserMessage.recipient_id == current_user.id,
                UserMessage.sender_id == other_user_id,
                UserMessage.read == False
            ).count()
            
            conversations.append({
                'other_user': other_user,
                'last_message': latest_message,
                'messages': conversation_messages,
                'unread_count': unread_count,
                'unread': unread_count > 0,
                'type': 'swap',
                'conversation_id': latest_message.id if latest_message else None
            })

    # Sort conversations by last message time
    conversations.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)

    selected_conversation = None
    if request.args.get('conversation_id'):
        conversation_id = int(request.args.get('conversation_id'))
        selected_conversation = next((c for c in conversations if c['conversation_id'] == conversation_id), None)
        
        # If no conversation found, try to find by user ID
        if not selected_conversation:
            user_id = int(request.args.get('conversation_id'))
            selected_conversation = next((c for c in conversations if c['other_user'].id == user_id), None)
        
        if selected_conversation:
            # Mark messages as read
            if selected_conversation['last_message']:
                UserMessage.query.filter_by(
                    recipient_id=current_user.id,
                    read=False,
                    id=selected_conversation['last_message'].id
                ).update({UserMessage.read: True})
                db.session.commit()

    return render_template('messages.html', 
                         conversations=conversations,
                         selected_conversation=selected_conversation)

@app.route('/messages/compose/<int:recipient_id>')
@login_required
def compose_message(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    return render_template('compose_message.html', recipient=recipient)

@app.route('/messages/send/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    content = request.form.get('content')
    if not content:
        flash('Message content is required')
        return redirect(url_for('messages'))

    # Create new message
    new_message = UserMessage(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content=content,
        read=False
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    flash('Message sent successfully')
    return redirect(url_for('messages', conversation_id=new_message.id))

# Add message count to navbar
@app.context_processor
def inject_message_count():
    if current_user.is_authenticated:
        unread_count = UserMessage.query.filter_by(
            recipient_id=current_user.id,
            read=False
        ).count()
        return dict(unread_messages=unread_count)
    return dict(unread_messages=0)

if __name__ == '__main__':
    app.run(debug=True)
