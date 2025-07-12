from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import csv
import io
from models import db, User, SwapRequest, Feedback, AdminMessage
from io import StringIO
from flask import make_response
from sqlalchemy.orm import aliased

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skill_swap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize db from models.py
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

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
    
    # Use aliases for the User table to avoid ambiguity
    from_user = aliased(User)
    to_user = aliased(User)
    
    swaps = db.session.query(
        SwapRequest,
        from_user.name.label('from_user_name'),
        to_user.name.label('to_user_name')
    ).join(
        from_user, SwapRequest.from_user_id == from_user.id
    ).join(
        to_user, SwapRequest.to_user_id == to_user.id
    ).all()
    
    return render_template('admin/monitor_swaps.html', swaps=swaps)

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
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('home'))
    
    # Create CSV report
    filename = f'skill_swap_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    # Get all users and their data
    users = User.query.all()
    swaps = SwapRequest.query.all()
    feedbacks = Feedback.query.all()
    
    # Create CSV content
    csv_content = []
    csv_content.append(['User Report'])
    csv_content.append(['ID', 'Name', 'Skills Offered', 'Skills Wanted', 'Banned'])
    for user in users:
        csv_content.append([
            user.id,
            user.name,
            user.skills_offered,
            user.skills_wanted,
            'Yes' if user.banned else 'No'
        ])
    
    csv_content.append(['\nSwap Report'])
    csv_content.append(['ID', 'From User', 'To User', 'Skills', 'Status', 'Created At'])
    for swap in swaps:
        csv_content.append([
            swap.id,
            swap.from_user.name,
            swap.to_user.name,
            f"{swap.skill_offered} -> {swap.skill_wanted}",
            swap.status,
            swap.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    csv_content.append(['\nFeedback Report'])
    csv_content.append(['ID', 'User', 'Rating', 'Review', 'Created At'])
    for feedback in feedbacks:
        csv_content.append([
            feedback.id,
            feedback.user.name,
            feedback.rating,
            feedback.review,
            feedback.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Create CSV file
    si = StringIO()
    cw = csv.writer(si)
    cw.writerows(csv_content)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv"
    return output

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

if __name__ == '__main__':
    app.run(debug=True)
