from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import csv
import io
from models import db, User, SwapRequest, Feedback, AdminMessage

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
    return render_template('home.html')

# --- User Registration ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        location = request.form.get('location')
        photo = request.form.get('photo')
        skills_offered = request.form.get('skills_offered')
        skills_wanted = request.form.get('skills_wanted')
        availability = request.form.get('availability')
        is_public = bool(request.form.get('is_public'))
        if User.query.filter_by(name=name).first():
            flash('User already exists')
            return redirect(url_for('register'))
        user = User(
            name=name,
            location=location,
            photo=photo,
            skills_offered=skills_offered,
            skills_wanted=skills_wanted,
            availability=availability,
            is_public=is_public,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

# --- User Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        user = User.query.filter_by(name=name).first()
        if user and check_password_hash(user.password_hash, password) and not user.banned:
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials or banned user')
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
    for user in users:
        user_statuses[user.id] = get_swap_status(current_user.id, user.id)
    return render_template('browse.html', users=users, user_statuses=user_statuses, pagination=pagination, q=q)

# --- Request Swap ---
@app.route('/request_swap/<int:user_id>')
@login_required
def request_swap(user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.banned or not target_user.is_public:
        flash('User not available for swaps.')
        return redirect(url_for('browse'))
    # For simplicity, use first skill offered/wanted
    skill_offered = (current_user.skills_offered or '').split(',')[0].strip() if current_user.skills_offered else ''
    skill_wanted = (target_user.skills_offered or '').split(',')[0].strip() if target_user.skills_offered else ''
    swap = SwapRequest(
        from_user_id=current_user.id,
        to_user_id=target_user.id,
        skill_offered=skill_offered,
        skill_wanted=skill_wanted
    )
    db.session.add(swap)
    db.session.commit()
    flash('Swap request sent!')
    return redirect(url_for('browse'))

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

# --- Admin Dashboard ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Admins only!')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')

@app.route('/admin/review_skills')
@login_required
def review_skills():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.filter(User.skills_offered.ilike('%spam%')).all()
    # Mark as banned for simplicity
    for user in users:
        user.banned = True
    db.session.commit()
    flash('Spammy skills banned.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/ban_users')
@login_required
def ban_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.filter_by(banned=False).all()
    return '<br>'.join([f"{u.name} <a href='{url_for('ban_user', user_id=u.id)}'>Ban</a>" for u in users])

@app.route('/admin/ban/<int:user_id>')
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    user.banned = True
    db.session.commit()
    flash('User banned.')
    return redirect(url_for('ban_users'))

@app.route('/admin/monitor_swaps')
@login_required
def monitor_swaps():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    swaps = SwapRequest.query.all()
    return '<br>'.join([f"{s.id}: {s.status} ({s.skill_offered} for {s.skill_wanted})" for s in swaps])

@app.route('/admin/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    if request.method == 'POST':
        msg = request.form['message']
        am = AdminMessage(message=msg)
        db.session.add(am)
        db.session.commit()
        flash('Message sent!')
        return redirect(url_for('admin_dashboard'))
    return '''<form method="POST">
        <label>Message:</label><input type="text" name="message" required><br>
        <button type="submit">Send</button>
    </form>'''

@app.route('/admin/download_reports')
@login_required
def download_reports():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    # Example: download all swaps as CSV
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'From', 'To', 'Skill Offered', 'Skill Wanted', 'Status', 'Created At'])
    for s in SwapRequest.query.all():
        cw.writerow([s.id, s.from_user_id, s.to_user_id, s.skill_offered, s.skill_wanted, s.status, s.created_at])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='swaps_report.csv')

if __name__ == '__main__':
    app.run(debug=True)
