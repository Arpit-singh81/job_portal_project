from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_file
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
import json
import bcrypt
from werkzeug.utils import secure_filename
import time
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

UPLOAD_FOLDER = 'static/resumes'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Database:
    def __init__(self):
        self.host = os.getenv('DB_HOST')
        self.user = os.getenv('DB_USER')
        self.password = os.getenv('DB_PASSWORD')
        self.database = os.getenv('DB_NAME')
    
    def connect(self):
        try:
            connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            return connection
        except Error as e:
            print(f"Database connection error: {e}")
            return None

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            if session.get('role') != required_role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
def send_otp_email(receiver_email, otp):
    """Send OTP email to user for password reset"""
    try:
        # Email configuration from environment variables
        smtp_host = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
        smtp_port = int(os.getenv('EMAIL_PORT', 587))
        email_user = os.getenv('EMAIL_USER')
        email_password = os.getenv('EMAIL_PASSWORD')
        email_from = os.getenv('EMAIL_FROM', email_user)
        
        if not all([email_user, email_password]):
            print("❌ Email configuration missing. Please check your .env file")
            print(f"📧 Demo OTP for {receiver_email}: {otp}")
            return False
        
        # Create message
        subject = "Job Portal - Password Reset OTP"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-code {{ font-size: 32px; font-weight: bold; color: #007bff; text-align: center; letter-spacing: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎯 Job Portal</h1>
                    <h2>Password Reset</h2>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>You requested a password reset for your Job Portal account. Use the OTP code below to reset your password:</p>
                    
                    <div class="otp-code">{otp}</div>
                    
                    <p>This OTP is valid for <strong>10 minutes</strong>. If you didn't request this reset, please ignore this email.</p>
                    
                    <p>Best regards,<br>Job Portal Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create message container - FIXED CLASS NAMES
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = receiver_email
        
        # Attach HTML content - FIXED CLASS NAME
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(email_user, email_password)
            server.send_message(msg)
        
        print(f"✅ OTP email sent to {receiver_email}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")
        print(f"📧 Demo OTP for {receiver_email}: {otp}")
        return False
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
                user = cursor.fetchone()
                
                if user and check_password(user['password_hash'], password):
                    session['user_id'] = user['user_id']
                    session['email'] = user['email']
                    session['role'] = user['role']
                    
                    cursor.execute("SELECT full_name, location FROM User_Profiles WHERE user_id = %s", (user['user_id'],))
                    profile = cursor.fetchone()
                    
                    if profile:
                        session['full_name'] = profile['full_name']
                        session['location'] = profile['location']
                    
                    cursor.close()
                    conn.close()
                    
                    flash(f'Welcome back, {session.get("full_name", session["email"])}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid email or password.', 'error')
                    
            except Error as e:
                flash(f'Login error: {str(e)}', 'error')
        
    return render_template('login.html')
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
                user = cursor.fetchone()
                
                if user:
                    # Generate OTP (6-digit code)
                    import random
                    otp = str(random.randint(100000, 999999))
                    
                    # Store OTP in session with expiration (10 minutes)
                    session['reset_otp'] = otp
                    session['reset_email'] = email
                    session['reset_otp_time'] = time.time()
                    
                    # Send OTP via email
                    email_sent = send_otp_email(email, otp)
                    
                    if email_sent:
                        flash('Password reset OTP has been sent to your email!', 'success')
                    else:
                        flash('OTP generated. Check terminal for demo OTP.', 'info')
                    
                    cursor.close()
                    conn.close()
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Email not found in our system.', 'error')
                    
            except Error as e:
                flash(f'Error: {str(e)}', 'error')
    
    return render_template('forgot_password.html')
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        flash('Please request a password reset first.', 'error')
        return redirect(url_for('forgot_password'))
    
    # Check if OTP expired (10 minutes)
    if time.time() - session.get('reset_otp_time', 0) > 600:
        flash('OTP has expired. Please request a new one.', 'error')
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
        session.pop('reset_otp_time', None)
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        if entered_otp == session.get('reset_otp'):
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Please complete OTP verification first.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('reset_password.html')
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor()
                hashed_password = hash_password(new_password)
                
                cursor.execute("UPDATE Users SET password_hash = %s WHERE email = %s", 
                             (hashed_password, session['reset_email']))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                # Clear reset session data
                session.pop('reset_otp', None)
                session.pop('reset_email', None)
                session.pop('reset_otp_time', None)
                
                flash('Password reset successfully! You can now login with your new password.', 'success')
                return redirect(url_for('login'))
                
            except Error as e:
                flash(f'Error resetting password: {str(e)}', 'error')
    
    return render_template('reset_password.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        full_name = request.form['full_name']
        location = request.form['location']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor()
                
                cursor.execute("SELECT user_id FROM Users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already registered.', 'error')
                    return render_template('register.html')
                
                hashed_password = hash_password(password)
                cursor.execute("INSERT INTO Users (email, password_hash, role) VALUES (%s, %s, %s)", (email, hashed_password, role))
                
                user_id = cursor.lastrowid
                
                cursor.execute("INSERT INTO User_Profiles (user_id, full_name, location) VALUES (%s, %s, %s)", (user_id, full_name, location))
                
                if role == 'job_seeker':
                    cursor.execute("INSERT INTO Job_Seekers (user_id, skills) VALUES (%s, %s)", (user_id, json.dumps([])))
                
                elif role == 'employer':
                    company_name = request.form.get('company_name', 'My Company')
                    industry = request.form.get('industry', 'Technology')
                    cursor.execute("INSERT INTO Employers (user_id, company_name, industry) VALUES (%s, %s, %s)", (user_id, company_name, industry))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
                
            except Error as e:
                flash(f'Registration error: {str(e)}', 'error')
        
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT COUNT(*) as count FROM Users")
            users_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM Jobs WHERE status='active'")
            jobs_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM Employers")
            employers_count = cursor.fetchone()['count']
            
            applications_count = 0
            try:
                cursor.execute("SELECT COUNT(*) as count FROM Applications")
                applications_count = cursor.fetchone()['count']
            except:
                applications_count = 0
            
            user_jobs = []
            user_applications = []
            
            if session['role'] == 'job_seeker':
                cursor.execute("""
                    SELECT j.job_id, j.title, a.status, a.applied_date
                    FROM Applications a
                    JOIN Jobs j ON a.job_id = j.job_id
                    WHERE a.seeker_id = (SELECT seeker_id FROM Job_Seekers WHERE user_id = %s)
                    ORDER BY a.applied_date DESC LIMIT 5
                """, (session['user_id'],))
                user_applications = cursor.fetchall()
                
            elif session['role'] == 'employer':
                cursor.execute("""
                    SELECT j.job_id, j.title, j.posted_date, COUNT(a.application_id) as applicant_count
                    FROM Jobs j
                    LEFT JOIN Applications a ON j.job_id = a.job_id
                    WHERE j.employer_id = (SELECT employer_id FROM Employers WHERE user_id = %s)
                    GROUP BY j.job_id ORDER BY j.posted_date DESC LIMIT 5
                """, (session['user_id'],))
                user_jobs = cursor.fetchall()
            
            cursor.execute("""
                SELECT j.job_id, j.title, j.location, j.job_type, e.company_name 
                FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id 
                WHERE j.status = 'active' ORDER BY j.posted_date DESC LIMIT 5
            """)
            recent_jobs = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return render_template('dashboard.html',
                                users_count=users_count,
                                jobs_count=jobs_count,
                                employers_count=employers_count,
                                applications_count=applications_count,
                                recent_jobs=recent_jobs,
                                user_jobs=user_jobs,
                                user_applications=user_applications)
            
        except Error as e:
            return f"Database error: {str(e)}"
    else:
        return "Database connection failed."

@app.route('/my-profile', methods=['GET', 'POST'])
@login_required
@role_required('job_seeker')
def my_profile():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            if request.method == 'POST':
                phone = request.form.get('phone')
                bio = request.form.get('bio')
                current_job_title = request.form.get('current_job_title')
                total_experience_years = request.form.get('total_experience_years')
                expected_salary = request.form.get('expected_salary')
                skills = request.form.get('skills')
                
                cursor.execute("UPDATE User_Profiles SET phone = %s, bio = %s WHERE user_id = %s", (phone, bio, session['user_id']))
                
                cursor.execute("""
                    UPDATE Job_Seekers SET current_job_title = %s, total_experience_years = %s,
                    expected_salary = %s, skills = %s WHERE user_id = %s
                """, (current_job_title, total_experience_years, expected_salary, 
                      json.dumps([s.strip() for s in skills.split(',')] if skills else []), 
                      session['user_id']))
                
                conn.commit()
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('my_profile'))
            
            cursor.execute("SELECT up.*, js.*, u.email FROM User_Profiles up JOIN Job_Seekers js ON up.user_id = js.user_id JOIN Users u ON up.user_id = u.user_id WHERE up.user_id = %s", (session['user_id'],))
            
            profile = cursor.fetchone()
            
            if profile and profile['skills']:
                try:
                    profile['skills_list'] = json.loads(profile['skills'])
                except:
                    profile['skills_list'] = []
            else:
                profile['skills_list'] = []
            
            experiences = []
            try:
                cursor.execute("SELECT e.* FROM Experience e JOIN Job_Seekers js ON e.seeker_id = js.seeker_id WHERE js.user_id = %s ORDER BY e.start_date DESC", (session['user_id'],))
                experiences = cursor.fetchall()
            except:
                pass
            
            cursor.close()
            conn.close()
            
            return render_template('job_seeker_profile.html', profile=profile, experiences=experiences)
            
        except Error as e:
            flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/add-experience', methods=['POST'])
@login_required
@role_required('job_seeker')
def add_experience():
    company = request.form.get('company')
    job_title = request.form.get('job_title')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    description = request.form.get('description')
    is_current = 1 if request.form.get('is_current') else 0
    
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Experience (
                    experience_id INT AUTO_INCREMENT PRIMARY KEY,
                    seeker_id INT NOT NULL,
                    company VARCHAR(255) NOT NULL,
                    job_title VARCHAR(255) NOT NULL,
                    start_date DATE NOT NULL,
                    end_date DATE NULL,
                    description TEXT,
                    is_current BOOLEAN DEFAULT FALSE,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (seeker_id) REFERENCES Job_Seekers(seeker_id)
                )
            """)
            
            cursor.execute("SELECT seeker_id FROM Job_Seekers WHERE user_id = %s", (session['user_id'],))
            seeker = cursor.fetchone()
            
            if seeker:
                cursor.execute("INSERT INTO Experience (seeker_id, company, job_title, start_date, end_date, description, is_current) VALUES (%s, %s, %s, %s, %s, %s, %s)", (seeker[0], company, job_title, start_date, end_date, description, is_current))
                
                conn.commit()
                flash('Work experience added successfully!', 'success')
            else:
                flash('Job seeker profile not found.', 'error')
            
            cursor.close()
            conn.close()
            
        except Error as e:
            flash(f'Error adding experience: {str(e)}', 'error')
    
    return redirect(url_for('my_profile'))

@app.route('/delete-experience/<int:experience_id>')
@login_required
@role_required('job_seeker')
def delete_experience(experience_id):
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor()
            
            cursor.execute("DELETE e FROM Experience e JOIN Job_Seekers js ON e.seeker_id = js.seeker_id WHERE e.experience_id = %s AND js.user_id = %s", (experience_id, session['user_id']))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Experience deleted successfully!', 'success')
            
        except Error as e:
            flash(f'Error deleting experience: {str(e)}', 'error')
    
    return redirect(url_for('my_profile'))

@app.route('/company/<int:company_id>/reviews')
@login_required
def company_reviews(company_id):
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT e.*, up.full_name as contact_person FROM Employers e JOIN Users u ON e.user_id = u.user_id JOIN User_Profiles up ON u.user_id = up.user_id WHERE e.employer_id = %s", (company_id,))
            company = cursor.fetchone()
            
            cursor.execute("""
                SELECT cr.*, up.full_name, CASE WHEN cr.is_anonymous = 1 THEN 'Anonymous' ELSE up.full_name END as display_name
                FROM Company_Reviews cr JOIN Users u ON cr.user_id = u.user_id JOIN User_Profiles up ON u.user_id = up.user_id
                WHERE cr.company_id = %s AND cr.is_approved = 1 ORDER BY cr.created_date DESC
            """, (company_id,))
            reviews = cursor.fetchall()
            
            user_has_reviewed = False
            if session['role'] == 'job_seeker':
                cursor.execute("SELECT review_id FROM Company_Reviews WHERE company_id = %s AND user_id = %s", (company_id, session['user_id']))
                user_has_reviewed = cursor.fetchone() is not None
            
            cursor.close()
            conn.close()
            
            return render_template('company_reviews.html', company=company, reviews=reviews, user_has_reviewed=user_has_reviewed)
            
        except Error as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('jobs_list'))
    
    return redirect(url_for('jobs_list'))

@app.route('/company/<int:company_id>/add-review', methods=['GET', 'POST'])
@login_required
@role_required('job_seeker')
def add_review(company_id):
    if request.method == 'POST':
        rating = request.form['rating']
        review_title = request.form['review_title']
        review_text = request.form['review_text']
        pros = request.form['pros']
        cons = request.form['cons']
        job_title = request.form.get('job_title', '')
        is_anonymous = 1 if 'is_anonymous' in request.form else 0
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor()
                
                cursor.execute("SELECT review_id FROM Company_Reviews WHERE company_id = %s AND user_id = %s", (company_id, session['user_id']))
                
                if cursor.fetchone():
                    flash('You have already reviewed this company.', 'error')
                    return redirect(url_for('company_reviews', company_id=company_id))
                
                cursor.execute("""
                    INSERT INTO Company_Reviews (company_id, user_id, job_title, rating, review_title, review_text, pros, cons, is_anonymous, is_approved)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (company_id, session['user_id'], job_title, rating, review_title, review_text, pros, cons, is_anonymous, 1))
                
                cursor.execute("""
                    UPDATE Employers SET avg_rating = (SELECT AVG(rating) FROM Company_Reviews WHERE company_id = %s AND is_approved = 1),
                    review_count = (SELECT COUNT(*) FROM Company_Reviews WHERE company_id = %s AND is_approved = 1) WHERE employer_id = %s
                """, (company_id, company_id, company_id))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Review submitted successfully!', 'success')
                return redirect(url_for('company_reviews', company_id=company_id))
                
            except Error as e:
                flash(f'Error: {str(e)}', 'error')
    
    return render_template('add_review.html', company_id=company_id)

@app.route('/schedule-interview/<int:application_id>', methods=['GET', 'POST'])
@login_required
@role_required('employer')
def schedule_interview(application_id):
    if request.method == 'POST':
        interview_date = request.form['interview_date']
        duration = request.form.get('duration', 60)
        interview_type = request.form.get('interview_type', 'video')
        meeting_link = request.form.get('meeting_link', '')
        location = request.form.get('location', '')
        notes = request.form.get('notes', '')
        job_id = request.form['job_id']
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                
                cursor.execute("""
                    INSERT INTO Interviews (application_id, interview_date, duration_minutes, interview_type, meeting_link, location, notes, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (application_id, interview_date, duration, interview_type, meeting_link, location, notes, session['user_id']))
                
                cursor.execute("UPDATE Applications SET status = 'under_review' WHERE application_id = %s", (application_id,))
                
                cursor.execute("""
                    SELECT js.user_id, j.title, e.company_name FROM Applications a
                    JOIN Job_Seekers js ON a.seeker_id = js.seeker_id
                    JOIN Jobs j ON a.job_id = j.job_id
                    JOIN Employers e ON j.employer_id = e.employer_id
                    WHERE a.application_id = %s
                """, (application_id,))
                applicant_info = cursor.fetchone()
                
                if applicant_info:
                    user_id = applicant_info['user_id']
                    job_title = applicant_info['title']
                    company_name = applicant_info['company_name']
                    notification_title = "Interview Scheduled"
                    notification_message = f"You have been scheduled for an interview for '{job_title}' at {company_name}. Date: {interview_date}, Type: {interview_type.replace('_', ' ').title()}"
                    
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS Notifications (
                            notification_id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            title VARCHAR(255) NOT NULL,
                            message TEXT NOT NULL,
                            is_read BOOLEAN DEFAULT FALSE,
                            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES Users(user_id)
                        )
                    """)
                    
                    cursor.execute("INSERT INTO Notifications (user_id, title, message) VALUES (%s, %s, %s)", (user_id, notification_title, notification_message))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Interview scheduled successfully!', 'success')
                return redirect(url_for('job_applicants', job_id=job_id))
                
            except Error as e:
                flash(f'Error scheduling interview: {str(e)}', 'error')
    
    db = Database()
    conn = db.connect()
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT a.*, j.title, j.job_id, p.full_name FROM Applications a
            JOIN Jobs j ON a.job_id = j.job_id
            JOIN Job_Seekers js ON a.seeker_id = js.seeker_id
            JOIN User_Profiles p ON js.user_id = p.user_id
            WHERE a.application_id = %s
        """, (application_id,))
        application = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return render_template('schedule_interview.html', application=application)
    
    return redirect(url_for('my_jobs'))

@app.route('/my-interviews')
@login_required
def my_interviews():
    db = Database()
    conn = db.connect()
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        if session['role'] == 'job_seeker':
            cursor.execute("""
                SELECT i.*, j.title, e.company_name, up.full_name as employer_name, a.status as application_status
                FROM Interviews i JOIN Applications a ON i.application_id = a.application_id
                JOIN Jobs j ON a.job_id = j.job_id JOIN Employers e ON j.employer_id = e.employer_id
                JOIN Users u ON e.user_id = u.user_id JOIN User_Profiles up ON u.user_id = up.user_id
                WHERE a.seeker_id = (SELECT seeker_id FROM Job_Seekers WHERE user_id = %s) ORDER BY i.interview_date DESC
            """, (session['user_id'],))
        
        elif session['role'] == 'employer':
            cursor.execute("""
                SELECT i.*, j.title, up.full_name as candidate_name, a.status as application_status
                FROM Interviews i JOIN Applications a ON i.application_id = a.application_id
                JOIN Jobs j ON a.job_id = j.job_id JOIN Job_Seekers js ON a.seeker_id = js.seeker_id
                JOIN User_Profiles up ON js.user_id = up.user_id
                WHERE i.created_by = %s ORDER BY i.interview_date DESC
            """, (session['user_id'],))
        
        interviews = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('my_interviews.html', interviews=interviews)
    
    return redirect(url_for('dashboard'))

@app.route('/notifications')
@login_required
def notifications():
    db = Database()
    conn = db.connect()
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Notifications (
                notification_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(user_id)
            )
        """)
        
        cursor.execute("SELECT * FROM Notifications WHERE user_id = %s ORDER BY created_date DESC", (session['user_id'],))
        notifications = cursor.fetchall()
        
        cursor.execute("UPDATE Notifications SET is_read = 1 WHERE user_id = %s AND is_read = 0", (session['user_id'],))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return render_template('notifications.html', notifications=notifications)
    
    return redirect(url_for('dashboard'))

@app.route('/upload-resume', methods=['GET', 'POST'])
@login_required
@role_required('job_seeker')
def upload_resume():
    if request.method == 'POST':
        if 'resume' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['resume']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"resume_{session['user_id']}_{int(time.time())}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(file_path)
            
            db = Database()
            conn = db.connect()
            
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE Job_Seekers SET resume_file_path = %s, resume_original_filename = %s WHERE user_id = %s", (file_path, filename, session['user_id']))
                    
                    conn.commit()
                    cursor.close()
                    conn.close()
                    
                    flash('Resume uploaded successfully!', 'success')
                    return redirect(url_for('dashboard'))
                    
                except Error as e:
                    flash(f'Error saving resume info: {str(e)}', 'error')
        
        else:
            flash('Invalid file type.', 'error')
    
    return render_template('upload_resume.html')

@app.route('/download-resume/<int:seeker_id>')
@login_required
def download_resume(seeker_id):
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT js.resume_file_path, js.resume_original_filename FROM Job_Seekers js WHERE js.seeker_id = %s", (seeker_id,))
            resume_info = cursor.fetchone()
            
            if not resume_info or not resume_info['resume_file_path']:
                flash('Resume not found.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
            
            if session['role'] == 'employer':
                cursor.execute("""
                    SELECT a.application_id FROM Applications a
                    JOIN Jobs j ON a.job_id = j.job_id
                    JOIN Employers e ON j.employer_id = e.employer_id
                    WHERE a.seeker_id = %s AND e.user_id = %s LIMIT 1
                """, (seeker_id, session['user_id']))
                has_access = cursor.fetchone() is not None
                
                if not has_access:
                    flash('You do not have permission to download this resume.', 'error')
                    return redirect(request.referrer or url_for('dashboard'))
            
            elif session['role'] == 'job_seeker':
                cursor.execute("SELECT seeker_id FROM Job_Seekers WHERE seeker_id = %s AND user_id = %s", (seeker_id, session['user_id']))
                is_owner = cursor.fetchone() is not None
                
                if not is_owner:
                    flash('You can only download your own resume.', 'error')
                    return redirect(request.referrer or url_for('dashboard'))
            
            cursor.close()
            conn.close()
            
            if os.path.exists(resume_info['resume_file_path']):
                return send_file(
                    resume_info['resume_file_path'],
                    as_attachment=True,
                    download_name=resume_info['resume_original_filename'] or 'resume.pdf'
                )
            else:
                flash('Resume file not found.', 'error')
                return redirect(request.referrer or url_for('dashboard'))
                
        except Error as e:
            flash(f'Error downloading resume: {str(e)}', 'error')
            return redirect(request.referrer or url_for('dashboard'))
    
    return redirect(url_for('dashboard'))

@app.route('/apply-job-with-resume/<int:job_id>', methods=['POST'])
@login_required
@role_required('job_seeker')
def apply_job_with_resume(job_id):
    cover_letter = request.form['cover_letter']
    use_existing_resume = 'use_existing_resume' in request.form
    
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT seeker_id, resume_file_path FROM Job_Seekers WHERE user_id = %s", (session['user_id'],))
            seeker = cursor.fetchone()
            
            if not seeker:
                flash('Job seeker profile not found.', 'error')
                return redirect(url_for('dashboard'))
            
            if use_existing_resume and not seeker['resume_file_path']:
                flash('No resume found. Please upload a resume first.', 'error')
                return redirect(url_for('upload_resume'))
            
            cursor.execute("SELECT application_id FROM Applications WHERE job_id = %s AND seeker_id = %s", (job_id, seeker['seeker_id']))
            
            if cursor.fetchone():
                flash('You have already applied for this job.', 'error')
                return redirect(url_for('jobs_list'))
            
            cursor.execute("INSERT INTO Applications (job_id, seeker_id, cover_letter) VALUES (%s, %s, %s)", (job_id, seeker['seeker_id'], cover_letter))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Application submitted successfully!', 'success')
            return redirect(url_for('my_applications'))
            
        except Error as e:
            flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('jobs_list'))

@app.route('/add-job', methods=['GET', 'POST'])
@login_required
@role_required('employer')
def add_job():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        requirements = request.form['requirements']
        location = request.form['location']
        job_type = request.form['job_type']
        salary_min = request.form.get('salary_min')
        salary_max = request.form.get('salary_max')
        skills = request.form['skills']
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor()
                
                cursor.execute("SELECT employer_id FROM Employers WHERE user_id = %s", (session['user_id'],))
                employer = cursor.fetchone()
                
                if not employer:
                    flash('Employer profile not found.', 'error')
                    return redirect(url_for('dashboard'))
                
                cursor.execute("""
                    INSERT INTO Jobs (employer_id, title, description, requirements, location, job_type, salary_range_min, salary_range_max, skills_required)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (employer[0], title, description, requirements, location, job_type, salary_min, salary_max, json.dumps([s.strip() for s in skills.split(',')])))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Job posted successfully!', 'success')
                return redirect(url_for('my_jobs'))
                
            except Error as e:
                flash(f'Error: {str(e)}', 'error')
        
    return render_template('add_job.html')

@app.route('/my-jobs')
@login_required
@role_required('employer')
def my_jobs():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT j.*, e.company_name, COUNT(a.application_id) as applicant_count
                FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id 
                LEFT JOIN Applications a ON j.job_id = a.job_id
                WHERE e.user_id = %s GROUP BY j.job_id ORDER BY j.posted_date DESC
            """, (session['user_id'],))
            jobs = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return render_template('my_jobs.html', jobs=jobs)
            
        except Error as e:
            return f"Database error: {str(e)}"
    else:
        return "Database connection failed."

@app.route('/job-applicants/<int:job_id>')
@login_required
@role_required('employer')
def job_applicants(job_id):
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT j.job_id, j.title, j.description, e.company_name
                FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id
                WHERE j.job_id = %s AND e.user_id = %s
            """, (job_id, session['user_id']))
            
            job = cursor.fetchone()
            
            if not job:
                flash('Job not found or access denied.', 'error')
                return redirect(url_for('my_jobs'))
            
            cursor.execute("""
                SELECT a.application_id, js.seeker_id, a.applied_date, a.status, a.cover_letter,
                       p.full_name, u.email, p.phone, p.location, p.bio, js.resume_text,
                       js.skills, js.resume_file_path, js.resume_original_filename,
                       js.total_experience_years, js.current_job_title, js.expected_salary
                FROM Applications a JOIN Job_Seekers js ON a.seeker_id = js.seeker_id
                JOIN Users u ON js.user_id = u.user_id JOIN User_Profiles p ON u.user_id = p.user_id
                WHERE a.job_id = %s ORDER BY a.applied_date DESC
            """, (job_id,))
            
            applicants = cursor.fetchall()
            
            for applicant in applicants:
                if applicant['skills']:
                    try:
                        applicant['skills_list'] = json.loads(applicant['skills'])
                    except:
                        applicant['skills_list'] = []
                else:
                    applicant['skills_list'] = []
            
            cursor.close()
            conn.close()
            
            return render_template('job_applicants.html', job=job, applicants=applicants)
            
        except Error as e:
            flash(f'Database error: {str(e)}', 'error')
            return redirect(url_for('my_jobs'))
    else:
        flash('Database connection failed.', 'error')
        return redirect(url_for('my_jobs'))

@app.route('/jobs')
@login_required
def jobs_list():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            search_query = request.args.get('search', '')
            company_query = request.args.get('company', '')
            location_query = request.args.get('location', '')
            job_types = request.args.getlist('job_type')
            salary_min = request.args.get('salary_min')
            salary_max = request.args.get('salary_max')
            
            base_query = """
                SELECT j.*, e.company_name, e.avg_rating, e.review_count
                FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id 
                WHERE j.status = 'active'
            """
            
            params = []
            
            if search_query:
                base_query += " AND (j.title LIKE %s OR j.description LIKE %s OR j.skills_required LIKE %s)"
                params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
            
            if company_query:
                base_query += " AND e.company_name LIKE %s"
                params.append(f'%{company_query}%')
            
            if location_query:
                base_query += " AND j.location LIKE %s"
                params.append(f'%{location_query}%')
            
            if job_types:
                placeholders = ', '.join(['%s'] * len(job_types))
                base_query += f" AND j.job_type IN ({placeholders})"
                params.extend(job_types)
            
            if salary_min:
                base_query += " AND j.salary_range_min >= %s"
                params.append(salary_min)
            
            if salary_max:
                base_query += " AND j.salary_range_max <= %s"
                params.append(salary_max)
            
            base_query += " ORDER BY j.posted_date DESC"
            
            cursor.execute(base_query, params)
            jobs = cursor.fetchall()
            
            if session['role'] == 'job_seeker':
                cursor.execute("SELECT job_id FROM Applications WHERE seeker_id = (SELECT seeker_id FROM Job_Seekers WHERE user_id = %s)", (session['user_id'],))
                applied_jobs = [row['job_id'] for row in cursor.fetchall()]
                
                for job in jobs:
                    job['has_applied'] = job['job_id'] in applied_jobs
            
            cursor.close()
            conn.close()
            
            return render_template('jobs_list.html', jobs=jobs)
            
        except Error as e:
            return f"Database error: {str(e)}"
    else:
        return "Database connection failed."

@app.route('/apply-job/<int:job_id>', methods=['GET', 'POST'])
@login_required
@role_required('job_seeker')
def apply_job(job_id):
    if request.method == 'POST':
        cover_letter = request.form['cover_letter']
        use_existing_resume = 'use_existing_resume' in request.form
        
        db = Database()
        conn = db.connect()
        
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                
                cursor.execute("SELECT seeker_id FROM Job_Seekers WHERE user_id = %s", (session['user_id'],))
                seeker = cursor.fetchone()
                
                if not seeker:
                    flash('Job seeker profile not found.', 'error')
                    return redirect(url_for('dashboard'))
                
                resume_file_path = None
                resume_filename = None
                
                if 'resume' in request.files and request.files['resume'].filename:
                    file = request.files['resume']
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        unique_filename = f"resume_{session['user_id']}_{int(time.time())}_{filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        
                        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                        file.save(file_path)
                        
                        resume_file_path = file_path
                        resume_filename = filename
                        
                        cursor.execute("UPDATE Job_Seekers SET resume_file_path = %s, resume_original_filename = %s WHERE user_id = %s", (file_path, filename, session['user_id']))
                
                elif use_existing_resume:
                    cursor.execute("SELECT resume_file_path FROM Job_Seekers WHERE user_id = %s", (session['user_id'],))
                    existing_resume = cursor.fetchone()
                    if existing_resume and existing_resume['resume_file_path']:
                        resume_file_path = existing_resume['resume_file_path']
                
                cursor.execute("SELECT application_id FROM Applications WHERE job_id = %s AND seeker_id = %s", (job_id, seeker['seeker_id']))
                if cursor.fetchone():
                    flash('You have already applied for this job.', 'error')
                    return redirect(url_for('jobs_list'))
                
                cursor.execute("INSERT INTO Applications (job_id, seeker_id, cover_letter) VALUES (%s, %s, %s)", (job_id, seeker['seeker_id'], cover_letter))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Application submitted successfully!', 'success')
                return redirect(url_for('my_applications'))
                
            except Error as e:
                flash(f'Error: {str(e)}', 'error')
    
    db = Database()
    conn = db.connect()
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT resume_file_path FROM Job_Seekers WHERE user_id = %s", (session['user_id'],))
        seeker = cursor.fetchone()
        
        has_resume = seeker and seeker['resume_file_path']
        
        cursor.execute("SELECT j.*, e.company_name FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id WHERE j.job_id = %s", (job_id,))
        job = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return render_template('apply_job.html', job_id=job_id, has_resume=has_resume, job=job)
    
    return redirect(url_for('jobs_list'))

@app.route('/my-applications')
@login_required
@role_required('job_seeker')
def my_applications():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT a.*, j.title, j.location, e.company_name, j.job_type
                FROM Applications a JOIN Jobs j ON a.job_id = j.job_id
                JOIN Employers e ON j.employer_id = e.employer_id
                WHERE a.seeker_id = (SELECT seeker_id FROM Job_Seekers WHERE user_id = %s)
                ORDER BY a.applied_date DESC
            """, (session['user_id'],))
            
            applications = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return render_template('my_applications.html', applications=applications)
            
        except Error as e:
            return f"Database error: {str(e)}"
    else:
        return "Database connection failed."

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/api/stats')
def api_stats():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT COUNT(*) as users FROM Users")
            users = cursor.fetchone()
            
            cursor.execute("SELECT COUNT(*) as jobs FROM Jobs")
            jobs = cursor.fetchone()
            
            cursor.execute("SELECT COUNT(*) as employers FROM Employers")
            employers = cursor.fetchone()
            
            cursor.execute("SELECT COUNT(*) as seekers FROM Job_Seekers")
            seekers = cursor.fetchone()
            
            applications = {'applications': 0}
            try:
                cursor.execute("SELECT COUNT(*) as applications FROM Applications")
                applications = cursor.fetchone()
            except:
                pass
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'data': {
                    'users': users['users'],
                    'jobs': jobs['jobs'],
                    'employers': employers['employers'],
                    'job_seekers': seekers['seekers'],
                    'applications': applications['applications']
                }
            })
            
        except Error as e:
            return jsonify({'status': 'error', 'message': str(e)})
    else:
        return jsonify({'status': 'error', 'message': 'Database connection failed'})

@app.route('/api/jobs')
def api_jobs():
    db = Database()
    conn = db.connect()
    
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT j.job_id, j.title, j.description, j.location, j.job_type,
                       j.salary_range_min, j.salary_range_max, j.posted_date,
                       e.company_name, e.industry
                FROM Jobs j JOIN Employers e ON j.employer_id = e.employer_id
                WHERE j.status = 'active' ORDER BY j.posted_date DESC
            """)
            jobs = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'data': jobs
            })
            
        except Error as e:
            return jsonify({'status': 'error', 'message': str(e)})
    else:
        return jsonify({'status': 'error', 'message': 'Database connection failed'})

if __name__ == '__main__':
    print("🚀 Starting Job Portal...")
    print("📊 Database: job_portal")
    print("🔐 Authentication: Enabled")
    print("👥 Role-based access: Job Seekers & Employers")
    print("🌐 Web interface: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)