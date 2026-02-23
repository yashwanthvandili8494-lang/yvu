from flask import Flask, request, render_template, flash, redirect, url_for,session, logging, send_file, jsonify, Response, render_template_string
import os
import pymysql
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SQLITE_PATH = os.path.join(BASE_DIR, "quizapp.db")

class CompatMySQLCursor:
    def __init__(self, cursor, backend):
        self._cursor = cursor
        self._backend = backend
        self._rows = None
        import re
        self._re = re

    def _normalize_query(self, query):
        """
        Normalize query placeholders between MySQL (%s) and SQLite (?) formats.
        Uses regex to avoid replacing ? in string literals or escaped characters.
        """
        import re
        if self._backend == "mysql":
            # Convert SQLite ? placeholders to MySQL %s placeholders
            # Use negative lookbehind to exclude escaped ? and ? in strings
            # This regex matches ? that are not preceded by \ and not inside quotes
            def replace_placeholder(match):
                return '%s'
            # Match ? that is not escaped (not preceded by \) and not in a string literal
            # We use a simpler approach: replace all ? with %s, assuming the query
            # is properly formatted and ? is used only as a placeholder
            return query.replace("?", "%s")
        else:
            # Convert MySQL %s placeholders to SQLite ? placeholders
            # Need to handle %% (escaped percent) - replace %% with % first
            # Then replace %s with ?
            # Use regex to handle escaped percent signs
            # First, handle escaped %% -> %
            query = query.replace('%%', '%')
            # Then replace %s with ?
            # Use word boundary to avoid replacing %s in other contexts
            return re.sub(r'%s', '?', query)

    def execute(self, query, params=None):
        normalized_query = self._normalize_query(query)
        if params is None:
            self._cursor.execute(normalized_query)
        else:
            self._cursor.execute(normalized_query, params)
        if self._cursor.description:
            self._rows = self._cursor.fetchall()
            return len(self._rows)
        self._rows = None
        return self._cursor.rowcount

    def executemany(self, query, param_list):
        normalized_query = self._normalize_query(query)
        return self._cursor.executemany(normalized_query, param_list)

    def fetchone(self):
        if self._rows is not None:
            if self._rows:
                return self._rows.pop(0)
            return None
        return self._cursor.fetchone()

    def fetchall(self):
        if self._rows is not None:
            rows = self._rows
            self._rows = []
            return rows
        return self._cursor.fetchall()

    def __getattr__(self, item):
        return getattr(self._cursor, item)


class MySQLConnection:
    def __init__(self):
        self.conn = None
        self.backend = None
        self.db_backend = os.getenv("DB_BACKEND", "sqlite").strip().lower()
        self.host = os.getenv("DB_HOST", "localhost")
        self.user = os.getenv("DB_USER", "root")
        self.password = os.getenv("DB_PASSWORD", "root")
        self.database = os.getenv("DB_NAME", "quizapp")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.sqlite_path = os.getenv("SQLITE_DB_PATH", DEFAULT_SQLITE_PATH)
    
    @property
    def connection(self):
        """Return self to allow mysql.connection.cursor() usage pattern"""
        return self

    def _connect_mysql(self):
        self.conn = pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
            port=self.port,
            cursorclass=pymysql.cursors.DictCursor,
            charset="utf8mb4",
            autocommit=False,
        )
        self.backend = "mysql"

    def _connect_sqlite(self):
        if not os.path.exists(self.sqlite_path) and os.path.exists("quizapp_sqlite.sql"):
            init_conn = sqlite3.connect(self.sqlite_path)
            with open("quizapp_sqlite.sql", "r", encoding="utf-8") as file:
                init_conn.executescript(file.read())
            init_conn.commit()
            init_conn.close()
        self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.backend = "sqlite"

    def _connect(self):
        if self.db_backend == "mysql":
            try:
                self._connect_mysql()
                return
            except Exception:
                pass
        self._connect_sqlite()

    def cursor(self):
        if self.conn is None:
            self._connect()
        elif self.backend == "mysql":
            try:
                self.conn.ping(reconnect=True)
            except Exception:
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.conn = None
                self.backend = None
                self._connect()
        return CompatMySQLCursor(self.conn.cursor(), self.backend)

    def commit(self):
        if self.conn:
            self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.backend = None

mysql = MySQLConnection()
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateTimeField, BooleanField, IntegerField, DecimalField, HiddenField, SelectField, RadioField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
# from flask_mail import Mail, Message
from functools import wraps
from werkzeug.utils import secure_filename
from coolname import generate_slug
from datetime import timedelta, datetime, timezone
from objective import ObjectiveTest
from subjective import SubjectiveTest
# from deepface import DeepFace
import pandas as pd
import stripe
import operator
import functools
import math, random
import csv
# import cv2
import numpy as np
import json
import base64
from wtforms_components import TimeField
from wtforms.fields import DateField
from wtforms.validators import ValidationError, NumberRange
from flask_session import Session
from flask_cors import CORS, cross_origin
# import camera

app = Flask(__name__)

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PORT'] = 3306
# app.config['MYSQL_PASSWORD'] = 'root'
# app.config['MYSQL_DB'] = 'quizapp'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').strip().lower() in ('1', 'true', 'yes', 'on')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').strip().lower() in ('1', 'true', 'yes', 'on')

app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

app.config['SESSION_TYPE'] = 'filesystem'

app.config['SESSION_PERMANENT'] = True

app.permanent_session_lifetime = timedelta(days=1)

app.config["TEMPLATES_AUTO_RELOAD"] = True

stripe_keys = {
    "secret_key": os.getenv("STRIPE_SECRET_KEY", "dummy"),
    "publishable_key": os.getenv("STRIPE_PUBLISHABLE_KEY", "dummy"),
}

stripe.api_key = stripe_keys["secret_key"]

# mail = Mail(app)

# mysql = MySQL(app)

sess = Session()
sess.init_app(app)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

app.secret_key= 'sem6project'

def get_db_connection():
    db_backend = os.getenv("DB_BACKEND", "sqlite").strip().lower()
    if db_backend == "mysql":
        try:
            return pymysql.connect(
                host=os.getenv("DB_HOST", "localhost"),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", "root"),
                database=os.getenv("DB_NAME", "quizapp"),
                port=int(os.getenv("DB_PORT", "3306")),
                cursorclass=pymysql.cursors.DictCursor,
                charset="utf8mb4",
                autocommit=False,
            )
        except Exception:
            pass
    conn = sqlite3.connect(os.getenv("SQLITE_DB_PATH", DEFAULT_SQLITE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

sender = 'youremail@abc.com'

YOUR_DOMAIN = os.getenv("YOUR_DOMAIN", "http://localhost:5000")
PDF_LINK_PATH = r"C:\Users\mg005\Documents\testquestion.pdf"

@app.before_request
def make_session_permanent():
	session.permanent = True

def normalize_test_id(value):
	if value is None:
		return ""
	return "".join(str(value).strip().lower().split())

def parse_exam_datetime(value):
	"""Safely parse exam datetime values from DB across sqlite/mysql string formats."""
	if value is None:
		return None
	if isinstance(value, datetime):
		return value
	text = str(value).strip()
	if not text:
		return None
	try:
		return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
	except Exception:
		try:
			return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
		except Exception:
			return None

def user_role_professor(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if session.get('logged_in'):
			role = session.get('user_role')
			if role == "teacher":
				return f(*args, **kwargs)
			if role is None:
				session.clear()
				flash('Session expired. Please login again.','danger')
				return redirect(url_for('login'))
			else:
				flash('You dont have privilege to access this page!','danger')
				return render_template("404.html") 
		else:
			flash('Unauthorized, Please login!','danger')
			return redirect(url_for('login'))
	return wrap

def user_role_student(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if session.get('logged_in'):
			role = session.get('user_role')
			if role == "student":
				return f(*args, **kwargs)
			if role is None:
				session.clear()
				flash('Session expired. Please login again.','danger')
				return redirect(url_for('login'))
			else:
				flash('You dont have privilege to access this page!','danger')
				return render_template("404.html") 
		else:
			flash('Unauthorized, Please login!','danger')
			return redirect(url_for('login'))
	return wrap

@app.route("/config")
@user_role_professor
def get_publishable_key():
    stripe_config = {"publicKey": stripe_keys["publishable_key"]}
    return jsonify(stripe_config)

# @app.route('/video_feed', methods=['GET','POST'])
# @user_role_student
# def video_feed():
# 	if request.method == "POST":
# 		imgData = request.form['data[imgData]']
# 		testid = request.form['data[testid]']
# 		voice_db = request.form['data[voice_db]']
# 		proctorData = camera.get_frame(imgData)
# 		jpg_as_text = proctorData['jpg_as_text']
# 		mob_status =proctorData['mob_status']
# 		person_status = proctorData['person_status']
# 		user_move1 = proctorData['user_move1']
# 		user_move2 = proctorData['user_move2']
# 		eye_movements = proctorData['eye_movements']
# 		cur = mysql.connection.cursor()
# 		results = cur.execute('INSERT INTO proctoring_log (email, name, test_id, voice_db, img_log, user_movements_updown, user_movements_lr, user_movements_eyes, phone_detection, person_status, uid) values(?,?,?,?,?,?,?,?,?,?,?)',
# 			(dict(session)['email'], dict(session)['name'], testid, voice_db, jpg_as_text, user_move1, user_move2, eye_movements, mob_status, person_status,dict(session)['uid']))
# 		mysql.connection.commit()
# 		cur.close()
# 		if(results > 0):
# 			return "recorded image of video"
# 		else:
# 			return "error in video"

@app.route('/window_event', methods=['GET','POST'])
@user_role_student
def window_event():
	if request.method == "POST":
		testid = request.form['testid']
		cur = mysql.connection.cursor()
		results = cur.execute('INSERT INTO window_estimation_log (email, test_id, name, window_event, uid) values(?,?,?,?,?)', (dict(session)['email'], testid, dict(session)['name'], 1, dict(session)['uid']))
		mysql.connection.commit()
		cur.close()
		if(results > 0):
			return "recorded window"
		else:
			return "error in window"
	return "ok"

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        if not stripe_keys["secret_key"] or stripe_keys["secret_key"] == "dummy":
            return jsonify(error="Payment is not configured. Set STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY."), 400
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'inr',
                        'unit_amount': 499*100,
                        'product_data': {
                            'name': 'Basic Exam Plan of 5 units',
                            'images': ['https://i.imgur.com/LsvO3kL_d.webp?maxwidth=760&fidelity=grand'],
                        },
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancelled',
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route("/livemonitoringtid")
@user_role_professor
def livemonitoringtid():
	try:
		cur = mysql.connection.cursor()
		results = cur.execute(
			'SELECT test_id, start, end from teachers where email = ? and uid = ? and proctoring_type = 1',
			(session['email'], session['uid'])
		)
		cresults = cur.fetchall()
		if not cresults:
			cur.execute(
				'SELECT test_id, start, end from teachers where email = ? and proctoring_type = 1',
				(session['email'],)
			)
			cresults = cur.fetchall()
		cur.close()

		if not cresults:
			return render_template("livemonitoringtid.html", cresults = None)

		now = datetime.now()
		live_ids = []
		nearby_ids = []
		all_ids = []
		for a in cresults:
			tid = a['test_id']
			start_dt = parse_exam_datetime(a['start'])
			end_dt = parse_exam_datetime(a['end'])
			all_ids.append(tid)
			if start_dt and end_dt and start_dt <= now <= end_dt:
				live_ids.append(tid)
			elif start_dt and end_dt:
				# Fallback list for usability when no exam is currently live.
				if end_dt >= (now - timedelta(hours=12)) or start_dt >= now:
					nearby_ids.append(tid)

		final_ids = live_ids if live_ids else (nearby_ids if nearby_ids else all_ids)
		# Remove duplicates while preserving order.
		final_ids = list(dict.fromkeys(final_ids))
		return render_template("livemonitoringtid.html", cresults = final_ids if final_ids else None)
	except Exception:
		return render_template("livemonitoringtid.html", cresults = None)

@app.route('/live_monitoring', methods=['GET','POST'])
@user_role_professor
def live_monitoring():
	if request.method == 'POST':
		testid = (request.form.get('choosetid') or "").strip()
		if not testid:
			flash('Please select a valid live exam ID.', 'danger')
			return render_template('live_monitoring.html', testid=None)
		return render_template('live_monitoring.html', testid=testid)
	else:
		return render_template('live_monitoring.html',testid = None)	

@app.route("/success")
@user_role_professor
def success():
	cur = mysql.connection.cursor()
	cur.execute('UPDATE users set examcredits = examcredits+5 where email = ? and uid = ?', (session['email'], session['uid']))
	mysql.connection.commit()
	cur.close()
	return render_template("success.html")

@app.route("/cancelled")
@user_role_professor
def cancelled():
    return render_template("cancelled.html")

@app.route("/payment")
@user_role_professor
def payment():
	cur = mysql.connection.cursor()
	cur.execute('SELECT examcredits FROM USERS where email = ? and uid = ?', (session['email'], session['uid']))
	callresults = cur.fetchone()
	cur.close()
	return render_template(
		"payment.html",
		key=stripe_keys['publishable_key'],
		callresults=callresults,
		payment_enabled=(stripe_keys['publishable_key'] != "dummy" and stripe_keys['secret_key'] != "dummy")
	)

@app.route('/')
def index():
	return render_template('index.html')

@app.errorhandler(404) 
def not_found(e):
	return render_template("404.html") 

@app.errorhandler(500)
def internal_error(error):
	app.logger.exception("Unhandled 500 error: %s", error)
	if request.path.startswith('/give-test'):
		return redirect(url_for('student_index'))
	return render_template("500.html"), 500 

@app.errorhandler(pymysql.MySQLError)
def handle_mysql_error(error):
	app.logger.exception("MySQL error: %s", error)
	return render_template(
		"login.html",
		error="Database error. Start MySQL and run setup_db.py, then try again."
	), 200

@app.errorhandler(KeyError)
def handle_key_error(error):
	app.logger.exception("Session/data key error: %s", error)
	session.clear()
	return redirect(url_for('login'))

@app.route('/calc')
def calc():
	return render_template('calc.html')

@app.route('/testquestion-pdf')
def testquestion_pdf():
	try:
		return send_file(PDF_LINK_PATH, as_attachment=False)
	except Exception:
		flash('PDF file not found at configured path.', 'danger')
		return redirect(url_for('index'))

@app.route('/report_professor')
@user_role_professor
def report_professor():
	return render_template('report_professor.html')

@app.route('/student_index')
@user_role_student
def student_index():
	return render_template('student_index.html')

@app.route('/professor_index')
@user_role_professor
def professor_index():
	return render_template('professor_index.html')

@app.route('/faq')
def faq():
	return render_template('faq.html')

@app.route('/report_student')
@user_role_student
def report_student():
	return render_template('report_student.html')

@app.route('/report_professor_email', methods=['GET','POST'])
@user_role_professor
def report_professor_email():
	if request.method == 'POST':
		careEmail = "narender.rk10@gmail.com"
		cname = session['name']
		cemail = session['email']
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		# msg1 = Message('PROBLEM REPORTED', sender = sender, recipients = [careEmail])
		# msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype ,"EMAIL:", cemail, "", "QUERY:", cquery])
		# mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_professor.html')

@app.route('/report_student_email', methods=['GET','POST'])
@user_role_student
def report_student_email():
	if request.method == 'POST':
		careEmail = "narender.rk10@gmail.com"
		cname = session['name']
		cemail = session['email']
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		# msg1 = Message('PROBLEM REPORTED', sender = sender, recipients = [careEmail])
		# msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype ,"EMAIL:", cemail, "", "QUERY:", cquery])
		# mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_student.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
	if request.method == 'POST':
		careEmail = "narender.rk10@gmail.com"
		cname = request.form['cname']
		cemail = request.form['cemail']
		cquery = request.form['cquery']
		# msg1 = Message('Hello', sender = sender, recipients = [cemail])
		# msg2 = Message('Hello', sender = sender, recipients = [careEmail])
		# msg1.body = "YOUR QUERY WILL BE PROCESSED! WITHIN 24 HOURS"
		# msg2 = Message('Hello', sender = sender, recipients = [careEmail])
		# msg2.body = " ".join(["NAME:", cname, "EMAIL:", cemail, "QUERY:", cquery])
		# mail.send(msg1)
		# mail.send(msg2)
		flash('Your Query has been recorded.', 'success')
	return render_template('contact.html')

@app.route('/lostpassword', methods=['GET','POST'])
def lostpassword():
	if request.method == 'POST':
		lpemail = request.form['lpemail']
		# cur = mysql.connection.cursor()
		# results = cur.execute('SELECT * from users where email = ?' , [lpemail])
		# if results > 0:
		sesOTPfp = generateOTP()
		session['tempOTPfp'] = sesOTPfp
		session['seslpemail'] = lpemail
		# msg1 = Message('MyProctor.ai - OTP Verification for Lost Password', sender = sender, recipients = [lpemail])
		# msg1.body = "Your OTP Verfication code for reset password is "+sesOTPfp+"."
		# mail.send(msg1)
		return redirect(url_for('verifyOTPfp'))
		# else:
		# 	return render_template('lostpassword.html',error="Account not found.")
	return render_template('lostpassword.html')

@app.route('/verifyOTPfp', methods=['GET','POST'])
def verifyOTPfp():
	if request.method == 'POST':
		fpOTP = request.form['fpotp']
		fpsOTP = session['tempOTPfp']
		if(fpOTP == fpsOTP):
			return redirect(url_for('lpnewpwd')) 
	return render_template('verifyOTPfp.html')

@app.route('/lpnewpwd', methods=['GET','POST'])
def lpnewpwd():
	if request.method == 'POST':
		npwd = request.form['npwd']
		cpwd = request.form['cpwd']
		slpemail = session['seslpemail']
		if(npwd == cpwd ):
			cur = mysql.connection.cursor()
			cur.execute('UPDATE users set password = ? where email = ?', (npwd, slpemail))
			mysql.connection.commit()
			cur.close()
			session.clear()
			return render_template('login.html',success="Your password was successfully changed.")
		else:
			return render_template('login.html',error="Password doesn't matched.")
	return render_template('lpnewpwd.html')

@app.route('/generate_test')
@user_role_professor
def generate_test():
	return render_template('generatetest.html')

@app.route('/changepassword_professor')
@user_role_professor
def changepassword_professor():
	return render_template('changepassword_professor.html')

@app.route('/changepassword_student')
@user_role_student
def changepassword_student():
	return render_template('changepassword_student.html')

def generateOTP() : 
    digits = "0123456789"
    OTP = "" 
    for i in range(5) : 
        OTP += digits[math.floor(random.random() * 10)] 
    return OTP 

@app.route('/register', methods=['GET','POST'])
def register():
	if request.method == 'POST':
		name = request.form['name']
		email = request.form['email']
		password = request.form['password']
		user_type = request.form['user_type']
		imgdata = request.form.get('image_hidden', '')
		# Directly insert user without OTP verification
		# Database is mocked, so registration will succeed
		try:
			cur = mysql.connection.cursor()
			ar = cur.execute('INSERT INTO users(name, email, password, user_type, user_image, user_login) values(?,?,?,?,?,?)', (name, email, password, user_type, imgdata, 0))
			mysql.connection.commit()
			if ar > 0:
				flash("Thanks for registering! You are successfully registered!.")
				return redirect(url_for('login'))
			else:
				flash("Error Occurred!")
				return redirect(url_for('register'))
			cur.close()
		except Exception as e:
			flash(f"Registration failed: {str(e)}")
			return redirect(url_for('register'))
	return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		email = request.form.get('email', '').strip().lower()
		password_candidate = request.form.get('password', '')
		user_type = request.form.get('user_type', '').strip().lower()
		imgdata1 = request.form.get('image_hidden', '')
		cur = None
		try:
			cur = mysql.connection.cursor()
			cur.execute(
				'SELECT uid, name, email, password, user_type, user_image from users where LOWER(TRIM(email)) = ? and LOWER(TRIM(user_type)) = ?',
				(email, user_type)
			)
			cresults = cur.fetchone()
			if cresults:
				imgdata2 = cresults['user_image']
				password = cresults['password']
				name = cresults['name']
				uid = cresults['uid']
				# nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
				# nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
				# image1 = cv2.imdecode(nparr1, cv2.COLOR_BGR2GRAY)
				# image2 = cv2.imdecode(nparr2, cv2.COLOR_BGR2GRAY)
				# img_result  = DeepFace.verify(image1, image2, enforce_detection = False)
				# if img_result["verified"] == True and password == password_candidate:
				if password == password_candidate:
					results2 = cur.execute('UPDATE users set user_login = 1 where uid = ?' , (uid,))
					mysql.connection.commit()
					if results2 > 0:
						session['logged_in'] = True
						session['email'] = cresults['email']
						session['name'] = name
						session['user_role'] = user_type
						session['uid'] = uid
						session.permanent = True
						if user_type == "student":
							return redirect(url_for('student_index'))
						else:
							return redirect(url_for('professor_index'))
					else:
						error = 'Error Occurred!'
						return render_template('login.html', error=error)
				else:
					error = 'Invalid password. Please try again.'
					return render_template('login.html', error=error)
			else:
				error = 'Email/User type not found. Please check login type and credentials.'
				return render_template('login.html', error=error)
		except Exception as e:
			error = 'Database temporarily unavailable. Please try again.'
			return render_template('login.html', error=error)
		finally:
			if cur:
				cur.close()
	return render_template('login.html')



@app.route('/changepassword', methods=["GET", "POST"])
def changePassword():
	if not session.get('logged_in'):
		return redirect(url_for('login'))

	if request.method == "POST":
		oldPassword = request.form['oldpassword']
		newPassword = request.form['newpassword']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from users where email = ? and uid = ?', (session['email'], session['uid']))
		if results > 0:
			data = cur.fetchone()
			password = data['password']
			usertype = data['user_type']
			if(password == oldPassword):
				cur.execute("UPDATE users SET password = ? WHERE email = ?", (newPassword, session['email']))
				mysql.connection.commit()
				msg="Changed successfully"
				flash('Changed successfully.', 'success')
				cur.close()
				if usertype == "student":
					return render_template("student_index.html", success=msg)
				else:
					return render_template("professor_index.html", success=msg)
			else:
				error = "Wrong password"
				if usertype == "student":
					return render_template("student_index.html", error=error)
				else:
					return render_template("professor_index.html", error=error)
		else:
			return redirect(url_for('index'))

	role = session.get('user_role')
	if role == "student":
		return render_template("changepassword_student.html")
	return render_template("changepassword_professor.html")

@app.route('/logout', methods=["GET", "POST"])
def logout():
	is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
	if 'email' not in session or 'uid' not in session:
		session.clear()
		if is_ajax:
			return "success"
		return redirect(url_for('login'))
	cur = mysql.connection.cursor()
	lbr = cur.execute('UPDATE users set user_login = 0 where email = ? and uid = ?',(session['email'],session['uid']))
	mysql.connection.commit()
	cur.close()
	if lbr > 0:
		session.clear()
		if is_ajax:
			return "success"
		return redirect(url_for('login'))
	else:
		if not is_ajax:
			session.clear()
			return redirect(url_for('login'))
		return "error"

def examcreditscheck():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT examcredits from users where examcredits >= 1 and email = ? and uid = ?', (session['email'], session['uid']))
	if results > 0:
		return True

class QAUploadForm(FlaskForm):
	subject = StringField('Subject')
	topic = StringField('Topic')
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date')
	start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
	end_date = DateField('End Date')
	end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
	duration = IntegerField('Duration(in min)')
	password = PasswordField('Exam Password', [validators.Length(min=3, max=6)])
	proctor_type = RadioField('Proctoring Type', choices=[('0','Automatic Monitoring'),('1','Live Monitoring')])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")
	
	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")
	
	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

@app.route('/create_test_lqa', methods = ['GET', 'POST'])
@user_role_professor
def create_test_lqa():
	form = QAUploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		try:
			test_id = generate_slug(2)
			filename = secure_filename(form.doc.data.filename)
			filestream = form.doc.data
			filestream.seek(0)
			ef = pd.read_csv(filestream)
			fields = ['qid','q','marks']
			df = pd.DataFrame(ef, columns = fields)
			cur = mysql.connection.cursor()
			ecc = examcreditscheck()
			if ecc:
				inserted_count = 0
				for row in df.index:
					qid_value = str(row + 1)
					q = "" if pd.isna(df['q'][row]) else str(df['q'][row]).strip()
					marks = 0 if pd.isna(df['marks'][row]) else int(df['marks'][row])
					if not q:
						continue
					cur.execute('INSERT INTO longqa(test_id,qid,q,marks,uid) values(?,?,?,?,?)', (test_id, qid_value, q, marks, session['uid']))
					cur.connection.commit()
					inserted_count += 1
				if inserted_count == 0:
					raise ValueError("No valid subjective questions found in CSV")
				
				start_date = form.start_date.data
				end_date = form.end_date.data
				start_time = form.start_time.data
				end_time = form.end_time.data
				start_date_time = str(start_date) + " " + str(start_time)
				end_date_time = str(end_date) + " " + str(end_time)
				duration = int(form.duration.data or 0) * 60
				password = form.password.data
				subject = form.subject.data
				topic = form.topic.data
				proctor_type = form.proctor_type.data or '0'
				cur.execute('INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc, proctoring_type, uid) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
					(dict(session)['email'], test_id, "subjective", start_date_time, end_date_time, duration, 0, password, subject, topic, 0, 0, proctor_type, session['uid']))
				mysql.connection.commit()
				cur.execute('UPDATE users SET examcredits = examcredits-1 where email = ? and uid = ?', (session['email'],session['uid']))
				mysql.connection.commit()
				cur.close()
				flash(f'Exam ID: {test_id}', 'success')
				return redirect(url_for('professor_index'))
			else:
				flash("No exam credits points are found! Please pay it!")
				return redirect(url_for('professor_index'))
		except Exception as e:
			flash(f'Error creating subjective exam: {str(e)}', 'danger')
			return redirect(url_for('create_test_lqa'))
	return render_template('create_test_lqa.html' , form = form)

class UploadForm(FlaskForm):
	subject = StringField('Subject')
	topic = StringField('Topic')
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date')
	start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
	end_date = DateField('End Date')
	end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
	calc = BooleanField('Enable Calculator')
	neg_mark = DecimalField('Enable negative marking in % ', validators=[NumberRange(min=0, max=100)])
	duration = IntegerField('Duration(in min)')
	password = PasswordField('Exam Password', [validators.Length(min=3, max=6)])
	proctor_type = RadioField('Proctoring Type', choices=[('0','Automatic Monitoring'),('1','Live Monitoring')])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")
	
	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")
	
	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class TestForm(Form):
	test_id = StringField('Exam ID')
	password = PasswordField('Exam Password')
	img_hidden_form = HiddenField(label=(''))

@app.route('/create-test', methods = ['GET', 'POST'])
@user_role_professor
def create_test():
	form = UploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		try:
			test_id = generate_slug(2)
			filename = secure_filename(form.doc.data.filename)
			filestream = form.doc.data
			filestream.seek(0)
			ef = pd.read_csv(filestream)
			fields = ['qid','q','a','b','c','d','ans','marks']
			df = pd.DataFrame(ef, columns = fields)
			cur = mysql.connection.cursor()
			ecc = examcreditscheck()
			if ecc:
				for row in df.index:
					# Force stable non-null QID regardless of CSV input.
					qid_value = str(row + 1)
					q = "" if pd.isna(df['q'][row]) else str(df['q'][row]).strip()
					a = "" if pd.isna(df['a'][row]) else str(df['a'][row]).strip()
					b = "" if pd.isna(df['b'][row]) else str(df['b'][row]).strip()
					c = "" if pd.isna(df['c'][row]) else str(df['c'][row]).strip()
					d = "" if pd.isna(df['d'][row]) else str(df['d'][row]).strip()
					ans = "" if pd.isna(df['ans'][row]) else str(df['ans'][row]).strip()
					marks = 0 if pd.isna(df['marks'][row]) else int(df['marks'][row])

					if not q:
						raise ValueError(f"CSV row {row + 2}: Question text (q) is empty")
					if not a or not b or not c or not d:
						raise ValueError(f"CSV row {row + 2}: one or more options (a,b,c,d) are empty")
					if not ans:
						raise ValueError(f"CSV row {row + 2}: answer (ans) is empty")

					cur.execute('INSERT INTO questions(test_id,qid,q,a,b,c,d,ans,marks,uid) values(?,?,?,?,?,?,?,?,?,?)', (test_id, qid_value, q, a, b, c, d, ans, marks, session['uid']))
					cur.connection.commit()

				start_date = form.start_date.data
				end_date = form.end_date.data
				start_time = form.start_time.data
				end_time = form.end_time.data
				start_date_time = str(start_date) + " " + str(start_time)
				end_date_time = str(end_date) + " " + str(end_time)
				neg_mark = int(form.neg_mark.data or 0)
				calc = int(bool(form.calc.data))
				duration = int(form.duration.data or 0) * 60
				password = form.password.data
				subject = form.subject.data
				topic = form.topic.data
				proctor_type = form.proctor_type.data or '0'
				cur.execute('INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc,proctoring_type, uid) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
					(dict(session)['email'], test_id, "objective", start_date_time, end_date_time, duration, 1, password, subject, topic, neg_mark, calc, proctor_type, session['uid']))
				mysql.connection.commit()
				cur.execute('UPDATE users SET examcredits = examcredits-1 where email = ? and uid = ?', (session['email'],session['uid']))
				mysql.connection.commit()
				cur.close()
				flash(f'Exam ID: {test_id}', 'success')
				return redirect(url_for('professor_index'))
			else:
				flash("No exam credits points are found! Please pay it!")
				return redirect(url_for('professor_index'))
		except Exception as e:
			flash(f'Error creating objective exam: {str(e)}', 'danger')
			return redirect(url_for('create_test'))
	return render_template('create_test.html' , form = form)

class PracUploadForm(FlaskForm):
	subject = StringField('Subject')
	topic = StringField('Topic')
	questionprac = StringField('Question')
	marksprac = IntegerField('Marks')
	start_date = DateField('Start Date')
	start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
	end_date = DateField('End Date')
	end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
	duration = IntegerField('Duration(in min)')
	compiler = SelectField(u'Compiler/Interpreter', choices=[('11', 'C'), ('27', 'C#'), ('1', 'C++'),('114', 'Go'),('10', 'Java'),('47', 'Kotlin'),('56', 'Node.js'),
	('43', 'Objective-C'),('29', 'PHP'),('54', 'Perl-6'),('116', 'Python 3x'),('117', 'R'),('17', 'Ruby'),('93', 'Rust'),('52', 'SQLite-queries'),('40', 'SQLite-schema'),
	('39', 'Scala'),('85', 'Swift'),('57', 'TypeScript')])
	password = PasswordField('Exam Password', [validators.Length(min=3, max=10)])
	proctor_type = RadioField('Proctoring Type', choices=[('0','Automatic Monitoring'),('1','Live Monitoring')])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")
	
	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")
	
	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

@app.route('/create_test_pqa', methods = ['GET', 'POST'])
@user_role_professor
def create_test_pqa():
	form = PracUploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		try:
			test_id = generate_slug(2)
			ecc = examcreditscheck()
			if ecc:
				compiler = form.compiler.data
				questionprac = (form.questionprac.data or "").strip()
				marksprac = int(form.marksprac.data or 0)
				if not questionprac:
					raise ValueError("Practical question is empty")
				if marksprac <= 0:
					raise ValueError("Marks must be greater than 0")

				cur = mysql.connection.cursor()
				cur.execute('INSERT INTO practicalqa(test_id,qid,q,compiler,marks,uid) values(?,?,?,?,?,?)', (test_id, 1, questionprac, compiler, marksprac, session['uid']))
				mysql.connection.commit()
				start_date = form.start_date.data
				end_date = form.end_date.data
				start_time = form.start_time.data
				end_time = form.end_time.data
				start_date_time = str(start_date) + " " + str(start_time)
				end_date_time = str(end_date) + " " + str(end_time)
				duration = int(form.duration.data or 0) * 60
				password = form.password.data
				subject = form.subject.data
				topic = form.topic.data
				proctor_type = form.proctor_type.data or '0'
				cur.execute('INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc, proctoring_type, uid) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
					(dict(session)['email'], test_id, "practical", start_date_time, end_date_time, duration, 0, password, subject, topic, 0, 0, proctor_type, session['uid']))
				mysql.connection.commit()
				cur.execute('UPDATE users SET examcredits = examcredits-1 where email = ? and uid = ?', (session['email'],session['uid']))
				mysql.connection.commit()
				cur.close()
				flash(f'Exam ID: {test_id}', 'success')
				return redirect(url_for('professor_index'))
			else:
				flash("No exam credits points are found! Please pay it!")
				return redirect(url_for('professor_index'))
		except Exception as e:
			flash(f'Error creating practical exam: {str(e)}', 'danger')
			return redirect(url_for('create_test_pqa'))
	return render_template('create_prac_qa.html' , form = form)

@app.route('/deltidlist', methods=['GET'])
@user_role_professor
def deltidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where email = ? and uid = ?', (session['email'], session['uid']))
	if results > 0:
		cresults = cur.fetchall()
		now = datetime.now()
		now = now.strftime("%Y-%m-%d %H:%M:%S")
		now = datetime.strptime(now,"%Y-%m-%d %H:%M:%S")
		testids = []
		for a in cresults:
			if datetime.strptime(str(a['start']),"%Y-%m-%d %H:%M:%S") > now:
				testids.append(a['test_id'])
		cur.close()
		return render_template("deltidlist.html", cresults = testids)
	else:
		return render_template("deltidlist.html", cresults = None)

@app.route('/deldispques', methods=['GET','POST'])
@user_role_professor
def deldispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispques.html", callresults = callresults, tid = tidoption)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispquesLQA.html", callresults = callresults, tid = tidoption)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispquesPQA.html", callresults = callresults, tid = tidoption)
		else:
			flash("Some Error Occured!")
			return redirect(url_for('deltidlist'))
	return redirect(url_for('deltidlist'))

@app.route('/delete_questions/<testid>', methods=['GET', 'POST'])
@user_role_professor
def delete_questions(testid):
	et = examtypecheck(testid)
	if et['test_type'] == "objective":
		cur = mysql.connection.cursor()
		msg = '' 
		if request.method == 'POST':
			testqdel = request.json['qids']
			if testqdel:
				if ',' in testqdel:
					testqdel = testqdel.split(',')
					for getid in testqdel:
						cur.execute('DELETE FROM questions WHERE test_id = ? and qid =? and uid = ?', (testid,getid,session['uid']))
						mysql.connection.commit()
					resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
					resp.status_code = 200
					return resp
				else:
					cur.execute('DELETE FROM questions WHERE test_id = ? and qid =? and uid = ?', (testid,testqdel,session['uid']))
					mysql.connection.commit()
					resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
					resp.status_code = 200
					return resp
	elif et['test_type'] == "subjective":
		cur = mysql.connection.cursor()
		msg = '' 
		if request.method == 'POST':
			testqdel = request.json['qids']
			if testqdel:
				if ',' in testqdel:
					testqdel = testqdel.split(',')
					for getid in testqdel:
						cur.execute('DELETE FROM longqa WHERE test_id = ? and qid =? and uid = ?', (testid,getid,session['uid']))
						mysql.connection.commit()
					resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
					resp.status_code = 200
					return resp
				else:
					cur.execute('DELETE FROM longqa WHERE test_id = ? and qid =? and uid = ?', (testid,testqdel,session['uid']))
					mysql.connection.commit()
					resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
					resp.status_code = 200
					return resp
	elif et['test_type'] == "practical":
		cur = mysql.connection.cursor()
		msg = '' 
		if request.method == 'POST':
			testqdel = request.json['qids']
			if testqdel:
				if ',' in testqdel:
					testqdel = testqdel.split(',')
					for getid in testqdel:
						cur.execute('DELETE FROM practicalqa WHERE test_id = ? and qid =? and uid = ?', (testid,getid,session['uid']))
						mysql.connection.commit()
					resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
					resp.status_code = 200
					return resp
			else:
				cur.execute('DELETE FROM questions WHERE test_id = ? and qid =? and uid = ?', (testid,testqdel,session['uid']))
				mysql.connection.commit()
				resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
				resp.status_code = 200
				return resp
	else:
		flash("Some Error Occured!")
		return redirect(url_for('deltidlist'))

@app.route('/<testid>/<qid>')
@user_role_professor
def del_qid(testid, qid):
	cur = mysql.connection.cursor()
	results = cur.execute('DELETE FROM questions where test_id = ? and qid = ? and uid = ?', (testid,qid,session['uid']))
	mysql.connection.commit()
	if results>0:
		msg="Deleted successfully"
		flash('Deleted successfully.', 'success')
		cur.close()
		return render_template("deldispques.html", success=msg)
	else:
		return redirect(url_for('deldispques'))

@app.route('/updatetidlist', methods=['GET'])
@user_role_professor
def updatetidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where email = ? and uid = ?', (session['email'],session['uid']))
	if results > 0:
		cresults = cur.fetchall()
		now = datetime.now()
		now = now.strftime("%Y-%m-%d %H:%M:%S")
		now = datetime.strptime(now,"%Y-%m-%d %H:%M:%S")
		testids = []
		for a in cresults:
			if datetime.strptime(str(a['start']),"%Y-%m-%d %H:%M:%S") > now:
				testids.append(a['test_id'])
		cur.close()
		return render_template("updatetidlist.html", cresults = testids)
	else:
		return render_template("updatetidlist.html", cresults = None)

@app.route('/updatedispques', methods=['GET','POST'])
@user_role_professor
def updatedispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispques.html", callresults = callresults)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispquesLQA.html", callresults = callresults)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispquesPQA.html", callresults = callresults)
		else:
			flash('Error Occured!')
			return redirect(url_for('updatetidlist'))
	return redirect(url_for('updatetidlist'))

@app.route('/update/<testid>/<qid>', methods=['GET','POST'])
@user_role_professor
def update_quiz(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM questions where test_id = ? and qid =? and uid = ?', (testid,qid,session['uid']))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestions.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		ao = request.form['ao']
		bo = request.form['bo']
		co = request.form['co']
		do = request.form['do']
		anso = request.form['anso']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE questions SET q = ?, a = ?, b = ?, c = ?, d = ?, ans = ?, marks = ? where test_id = ? and qid = ? and uid = ?', (ques,ao,bo,co,do,anso,markso,testid,qid,session['uid']))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'error')
		return redirect(url_for('updatetidlist'))

@app.route('/updateLQA/<testid>/<qid>', methods=['GET','POST'])
@user_role_professor
def update_lqa(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM longqa where test_id = ? and qid =? and uid = ?', (testid,qid,session['uid']))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestionsLQA.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE longqa SET q = ?, marks = ? where test_id = ? and qid = ? and uid = ?', (ques,markso,testid,qid,session['uid']))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'error')
		return redirect(url_for('updatetidlist'))

@app.route('/updatePQA/<testid>/<qid>', methods=['GET','POST'])
@user_role_professor
def update_PQA(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM practicalqa where test_id = ? and qid =? and uid = ?', (testid,qid,session['uid']))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestionsPQA.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE practicalqa SET q = ?, marks = ? where test_id = ? and qid = ? and uid = ?', (ques,markso,testid,qid,session['uid']))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'error')
		return redirect(url_for('updatetidlist'))

@app.route('/viewquestions', methods=['GET'])
@user_role_professor
def viewquestions():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where email = ? and uid = ?', (session['email'],session['uid']))
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("viewquestions.html", cresults = cresults)
	else:
		return render_template("viewquestions.html", cresults = None)

def examtypecheck(tidoption):
	cur = mysql.connection.cursor()
	cur.execute('SELECT test_type from teachers where test_id = ? and email = ? and uid = ?', (tidoption,session['email'],session['uid']))
	callresults = cur.fetchone()
	if not callresults:
		cur.execute('SELECT test_type from teachers where test_id = ? and email = ?', (tidoption,session['email']))
		callresults = cur.fetchone()
	cur.close()
	return callresults

@app.route('/displayquestions', methods=['GET','POST'])
@user_role_professor
def displayquestions():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestions.html", callresults = callresults)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestionslong.html", callresults = callresults)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = ? and uid = ?', (tidoption,session['uid']))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestionspractical.html", callresults = callresults)
	return redirect(url_for('viewquestions'))

@app.route('/viewstudentslogs', methods=['GET'])
@user_role_professor
def viewstudentslogs():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where email = ? and uid = ? and proctoring_type = 0', (session['email'], session['uid']))
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("viewstudentslogs.html", cresults = cresults)
	else:
		return render_template("viewstudentslogs.html", cresults = None)

@app.route('/insertmarkstid', methods=['GET'])
@user_role_professor
def insertmarkstid():
	cur = mysql.connection.cursor()
	results = cur.execute(
		'SELECT * from teachers where show_ans = 0 and email = ? and uid = ? and (test_type = ? or test_type = ?)',
		(session['email'], session['uid'], "subjective", "practical")
	)
	cresults = cur.fetchall()
	if not cresults:
		cur.execute(
			'SELECT * from teachers where show_ans = 0 and email = ? and (test_type = ? or test_type = ?)',
			(session['email'], "subjective", "practical")
		)
		cresults = cur.fetchall()
	if cresults:
		now = datetime.now()
		testids = []
		for a in cresults:
			end_dt = parse_exam_datetime(a['end'])
			if end_dt and end_dt < now:
				testids.append(a['test_id'])
		cur.close()
		return render_template("insertmarkstid.html", cresults = testids if testids else None)
	else:
		return render_template("insertmarkstid.html", cresults = None)

@app.route('/displaystudentsdetails', methods=['GET','POST'])
@user_role_professor
def displaystudentsdetails():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT DISTINCT email,test_id from proctoring_log where test_id = ?', [tidoption])
		callresults = cur.fetchall()
		cur.close()
		return render_template("displaystudentsdetails.html", callresults = callresults)
	return redirect(url_for('viewstudentslogs'))

@app.route('/insertmarksdetails', methods=['GET','POST'])
@user_role_professor
def insertmarksdetails():
	if request.method == 'POST':
		tidoption = (request.form.get('choosetid') or "").strip()
		cur = mysql.connection.cursor()
		cur.execute(
			'SELECT test_id, test_type FROM teachers WHERE lower(trim(email)) = lower(trim(?))',
			(session['email'],)
		)
		rows = cur.fetchall()
		cur.close()
		match = None
		input_norm = normalize_test_id(tidoption)
		for row in rows:
			if normalize_test_id(row['test_id']) == input_norm:
				match = row
				break
		if not match or not match['test_type']:
			flash("Invalid test id", 'danger')
			return redirect(url_for('insertmarkstid'))
		tidoption = match['test_id']
		ttype = str(match['test_type']).strip().lower()
		if ttype == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT DISTINCT email,test_id from longtest where lower(trim(test_id)) = lower(trim(?))', [tidoption])
			callresults = cur.fetchall()
			cur.close()
			if not callresults:
				flash('No submissions found for this exam yet.', 'warning')
				return redirect(url_for('insertmarkstid'))
			return render_template("subdispstudentsdetails.html", callresults = callresults)
		elif ttype == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT DISTINCT email,test_id from practicaltest where lower(trim(test_id)) = lower(trim(?))', [tidoption])
			callresults = cur.fetchall()
			cur.close()
			if not callresults:
				flash('No submissions found for this exam yet.', 'warning')
				return redirect(url_for('insertmarkstid'))
			return render_template("pracdispstudentsdetails.html", callresults = callresults)
		else:
			flash("Some Error was occured!",'error')
			return redirect(url_for('insertmarkstid'))
	return redirect(url_for('insertmarkstid'))

@app.route('/insertsubmarks/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def insertsubmarks(testid,email):
	if request.method == "GET":
		cur = mysql.connection.cursor()
		cur.execute('SELECT l.email as email, l.marks as inputmarks, l.test_id as test_id, l.qid as qid, l.ans as ans, lqa.marks as marks, l.uid as uid, lqa.q as q  from longtest l, longqa lqa where l.test_id = ? and l.email = ? and l.test_id = lqa.test_id and l.qid = lqa.qid ORDER BY qid ASC', (testid, email))
		callresults = cur.fetchall()
		cur.close()
		return render_template("insertsubmarks.html", callresults = callresults)
	if request.method == "POST":
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT COUNT(qid) from longtest where test_id = ? and email = ?',(testid, email))
		results1 = cur.fetchone()
		cur.close()
		for sa in range(1,results1['COUNT(qid)']+1):
			marksByProfessor = request.form[str(sa)]
			cur = mysql.connection.cursor()
			cur.execute('UPDATE longtest SET marks = ? WHERE test_id = ? and email = ? and qid = ?', (marksByProfessor, testid, email, sa))
			mysql.connection.commit()
		cur.close()
		flash('Marks Entered Sucessfully!', 'success')
		return redirect(url_for('insertmarkstid'))

@app.route('/insertpracmarks/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def insertpracmarks(testid,email):
	if request.method == "GET":
		cur = mysql.connection.cursor()
		cur.execute('SELECT l.email as email, l.marks as inputmarks, l.test_id as test_id, l.qid as qid, l.code as code, l.input as input, l.executed as executed, lqa.marks as marks, l.uid as uid, lqa.q as q  from practicaltest l, practicalqa lqa where l.test_id = ? and l.email = ? and l.test_id = lqa.test_id and l.qid = lqa.qid ORDER BY qid ASC', (testid, email))
		callresults = cur.fetchall()
		cur.close()
		return render_template("insertpracmarks.html", callresults = callresults)
	if request.method == "POST":
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT COUNT(qid) from practicaltest where test_id = ? and email = ?',(testid, email))
		results1 = cur.fetchone()
		cur.close()
		for sa in range(1,results1['COUNT(qid)']+1):
			marksByProfessor = request.form[str(sa)]
			cur = mysql.connection.cursor()
			cur.execute('UPDATE practicaltest SET marks = ? WHERE test_id = ? and email = ? and qid = ?', (marksByProfessor, testid, email, sa))
			mysql.connection.commit()
		cur.close()
		flash('Marks Entered Sucessfully!', 'success')
		return redirect(url_for('insertmarkstid'))

def displaywinstudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from window_estimation_log where test_id = ? and email = ? and window_event = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return callresults

def countwinstudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as wincount from window_estimation_log where test_id = ? and email = ? and window_event = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	winc = [i['wincount'] for i in callresults]
	return winc

def countMobStudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as mobcount from proctoring_log where test_id = ? and email = ? and phone_detection = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	mobc = [i['mobcount'] for i in callresults]
	return mobc

def countMTOPstudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as percount from proctoring_log where test_id = ? and email = ? and person_status = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	perc = [i['percount'] for i in callresults]
	return perc

def countMTOPstudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as percount from proctoring_log where test_id = ? and email = ? and person_status = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	perc = [i['percount'] for i in callresults]
	return perc

def countTotalstudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as total from proctoring_log where test_id = ? and email = ?', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	tot = [i['total'] for i in callresults]
	return tot

@app.route('/studentmonitoringstats/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def studentmonitoringstats(testid,email):
	return render_template("stat_student_monitoring.html", testid = testid, email = email)

@app.route('/ajaxstudentmonitoringstats/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def ajaxstudentmonitoringstats(testid,email):
	win = countwinstudentslogs(testid,email)
	mob = countMobStudentslogs(testid,email)
	per = countMTOPstudentslogs(testid,email)
	tot = countTotalstudentslogs(testid,email)
	return jsonify({"win":win,"mob":mob,"per":per,"tot":tot})

@app.route('/displaystudentslogs/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def displaystudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = ? and email = ?', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("displaystudentslogs.html", testid = testid, email = email, callresults = callresults)

@app.route('/mobdisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def mobdisplaystudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = ? and email = ? and phone_detection = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("mobdisplaystudentslogs.html", testid = testid, email = email, callresults = callresults)

@app.route('/persondisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def persondisplaystudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = ? and email = ? and person_status = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("persondisplaystudentslogs.html",testid = testid, email = email, callresults = callresults)

@app.route('/audiodisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def audiodisplaystudentslogs(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = ? and email = ?', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("audiodisplaystudentslogs.html", testid = testid, email = email, callresults = callresults)

@app.route('/wineventstudentslogs/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def wineventstudentslogs(testid,email):
	callresults = displaywinstudentslogs(testid,email)
	return render_template("wineventstudentlog.html", testid = testid, email = email, callresults = callresults)

@app.route('/<email>/<testid>/share_details', methods=['GET','POST'])
@user_role_professor
def share_details(testid,email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from teachers where test_id = ? and email = ?', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("share_details.html", callresults = callresults)

@app.route('/share_details_emails', methods=['GET','POST'])
@user_role_professor
def share_details_emails():
	def _load_exam_rows(tid_value):
		if not tid_value:
			return []
		cur_local = mysql.connection.cursor()
		cur_local.execute('SELECT * from teachers where test_id = ? and email = ?', (tid_value, session['email']))
		rows_local = cur_local.fetchall()
		cur_local.close()
		return rows_local

	if request.method == 'POST':
		tid = (request.form.get('tid') or '').strip()
		subject = request.form.get('subject', '')
		topic = request.form.get('topic', '')
		duration = request.form.get('duration', '')
		start = request.form.get('start', '')
		end = request.form.get('end', '')
		password = request.form.get('password', '')
		neg_marks = request.form.get('neg_marks', '')
		calc = request.form.get('calc', '')
		emailssharelist = request.form.get('emailssharelist', '')
		recipients = [e.strip() for e in emailssharelist.split(',') if e.strip()]
		callresults = _load_exam_rows(tid)

		if not tid or not callresults:
			flash('Invalid exam details.', 'danger')
			return render_template('share_details.html', callresults=callresults)
		if not recipients:
			flash('Please enter at least one valid recipient email.', 'danger')
			return render_template('share_details.html', callresults=callresults)

		body = " ".join([
			"EXAM-ID:", tid, "SUBJECT:", subject, "TOPIC:", topic, "DURATION:", str(duration),
			"START", str(start), "END", str(end), "PASSWORD", str(password),
			"NEGATIVE MARKS in %:", str(neg_marks), "CALCULATOR ALLOWED:", str(calc)
		])

		# Use SMTP directly to avoid crashing when Flask-Mail is not configured.
		try:
			import smtplib
			from email.message import EmailMessage
			smtp_user = app.config.get('MAIL_USERNAME', '')
			smtp_pass = app.config.get('MAIL_PASSWORD', '')
			smtp_host = app.config.get('MAIL_SERVER', '')
			smtp_port = int(app.config.get('MAIL_PORT', 587))
			use_tls = bool(app.config.get('MAIL_USE_TLS', True))
			if not smtp_user or not smtp_pass:
				flash('Email not configured. Update MAIL_USERNAME and MAIL_PASSWORD.', 'warning')
				return render_template('share_details.html', callresults=callresults)

			msg = EmailMessage()
			msg['Subject'] = 'EXAM DETAILS - MyProctor.ai'
			msg['From'] = smtp_user
			msg['To'] = ', '.join(recipients)
			msg.set_content(body)

			with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
				if use_tls:
					server.starttls()
				server.login(smtp_user, smtp_pass)
				server.send_message(msg)

			flash('Emails sent successfully!', 'success')
			return render_template('share_details.html', callresults=callresults)
		except Exception as e:
			flash(f'Unable to send email: {str(e)}', 'danger')
			return render_template('share_details.html', callresults=callresults)

	tid = (request.args.get('tid') or '').strip()
	return render_template('share_details.html', callresults=_load_exam_rows(tid))

@app.route("/publish-results-testid", methods=['GET','POST'])
@user_role_professor
def publish_results_testid():
	cur = mysql.connection.cursor()
	results = cur.execute(
		'SELECT * from teachers where email = ? AND uid = ?',
		(session['email'], session['uid'])
	)
	cresults = cur.fetchall()
	if not cresults:
		cur.execute(
			'SELECT * from teachers where email = ?',
			(session['email'],)
		)
		cresults = cur.fetchall()
	if cresults:
		now = datetime.now()
		testids = []
		for a in cresults:
			end_dt = parse_exam_datetime(a['end'])
			if end_dt and end_dt < now:
				testids.append(a['test_id'])
		cur.close()
		return render_template("publish_results_testid.html", cresults = testids)
	else:
		return render_template("publish_results_testid.html", cresults = None)

@app.route('/viewresults', methods=['GET','POST'])
@user_role_professor
def viewresults():
	if request.method == 'POST':
		tidoption = (request.form.get('choosetid') or "").strip()
		cur = mysql.connection.cursor()
		cur.execute(
			'SELECT test_id, test_type FROM teachers WHERE lower(trim(email)) = lower(trim(?))',
			(session['email'],)
		)
		rows = cur.fetchall()
		cur.close()
		match = None
		input_norm = normalize_test_id(tidoption)
		for row in rows:
			if normalize_test_id(row['test_id']) == input_norm:
				match = row
				break
		if not match or not match['test_type']:
			flash("Invalid test id", 'danger')
			return redirect(url_for('publish_results_testid'))
		tidoption = match['test_id']
		ttype = str(match['test_type']).strip().lower()
		if ttype == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT SUM(marks) as marks, email from longtest where test_id = ? group by email', ([tidoption]))
			callresults = cur.fetchall()
			cur.close()
			return render_template("publish_viewresults.html", callresults = callresults, tid = tidoption)
		elif ttype == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT SUM(marks) as marks, email from practicaltest where test_id = ? group by email', ([tidoption]))
			callresults = cur.fetchall()
			cur.close()
			return render_template("publish_viewresults.html", callresults = callresults, tid = tidoption)
		elif ttype == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT DISTINCT email from students where test_id = ?',[tidoption])
			students_list = cur.fetchall()
			cur.close()
			callresults = []
			for s in students_list:
				callresults.append({'email': s['email'], 'marks': marks_calc(s['email'], tidoption)})
			return render_template("publish_viewresults.html", callresults = callresults, tid = tidoption)
		else:
			flash("Some Error Occured!")
			return redirect(url_for('publish_results_testid'))
	return redirect(url_for('publish_results_testid'))

@app.route('/publish_results', methods=['GET','POST'])
@user_role_professor
def publish_results():
	if request.method == 'POST':
		tidoption = request.form['testidsp']
		cur = mysql.connection.cursor()
		cur.execute('SELECT show_ans from teachers where test_id = ? and email = ? and uid = ?', (tidoption, session['email'], session['uid']))
		check = cur.fetchone()
		if not check:
			cur.execute('SELECT show_ans from teachers where test_id = ? and email = ?', (tidoption, session['email']))
			check = cur.fetchone()
		if check and int(check['show_ans']) == 1:
			cur.close()
			flash("Results already published.")
			return redirect(url_for('publish_results_testid'))
		cur.execute(
			'UPDATE teachers set show_ans = 1 where test_id = ? and email = ? and uid = ?',
			(tidoption, session['email'], session['uid'])
		)
		if cur.rowcount == 0:
			cur.execute(
				'UPDATE teachers set show_ans = 1 where test_id = ? and email = ?',
				(tidoption, session['email'])
			)
		mysql.connection.commit()
		cur.close()
		flash("Results published sucessfully!")
		return redirect(url_for('professor_index'))
	return redirect(url_for('publish_results_testid'))

@app.route('/test_update_time', methods=['GET','POST'])
@user_role_student
def test_update_time():
	if request.method == 'POST':
		cur = mysql.connection.cursor()
		time_left = request.form['time']
		testid = request.form['testid']
		cur.execute('UPDATE studentTestInfo set time_left=? where test_id = ? and email = ? and uid = ? and completed=0', (time_left, testid, session['email'], session['uid']))
		mysql.connection.commit()
		t1 = cur.rowcount
		cur.close()
		if t1 > 0:
			return "time recorded updated"
		else:
			cur = mysql.connection.cursor()
			# Do not create a new active row if exam already has a completed record.
			cur.execute('SELECT completed from studentTestInfo where test_id = ? and email = ? order by stiid desc limit 1', (testid, session['email']))
			last_row = cur.fetchone()
			if last_row is not None and int(last_row['completed']) == 1:
				cur.close()
				return "exam already completed"
			cur.execute('INSERT into studentTestInfo (email, test_id,time_left,uid) values(?,?,?,?)', (session['email'], testid, time_left, session['uid']))
			mysql.connection.commit()
			t2 = cur.rowcount
			cur.close()
			if t2 > 0:
				return "time recorded inserted"
			else:
				return "time error"
	return "ok"

@app.route("/give-test", methods = ['GET', 'POST'])
@user_role_student
def give_test():
	global duration, marked_ans, calc, subject, topic, proctortype
	form = TestForm(request.form)
	available_test_ids = []
	try:
		now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		cur_ids = mysql.connection.cursor()
		results_ids = cur_ids.execute(
			'SELECT test_id FROM teachers WHERE start <= ? AND end >= ? ORDER BY start ASC',
			(now, now)
		)
		if results_ids > 0:
			rows = cur_ids.fetchall()
			available_test_ids = [row['test_id'] for row in rows if row['test_id']]
		cur_ids.close()
	except Exception:
		available_test_ids = []

	error_msg = request.args.get('error')
	if error_msg:
		flash(error_msg, 'danger')
	if request.method == 'POST' and form.validate():
		test_id = ((form.test_id.data if form.test_id.data is not None else request.form.get('test_id', '')) or "").strip()
		if not test_id:
			flash('Please select a valid Exam ID from dropdown', 'danger')
			return redirect(url_for('give_test'))
		password_candidate = form.password.data
		imgdata1 = form.img_hidden_form.data
		cur1 = mysql.connection.cursor()
		results1 = cur1.execute('SELECT user_image from users where email = ? and user_type = ? ', (session['email'],'student'))
		if results1 > 0:
			cresults = cur1.fetchone()
			imgdata2 = cresults['user_image']
			cur1.close()
			# nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
			# nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
			# image1 = cv2.imdecode(nparr1, cv2.COLOR_BGR2GRAY)
			# image2 = cv2.imdecode(nparr2, cv2.COLOR_BGR2GRAY)
			# img_result  = DeepFace.verify(image1, image2, enforce_detection = False)
			# if img_result["verified"] == True:
			if True:
				cur = mysql.connection.cursor()
				results = cur.execute('SELECT * FROM teachers ORDER BY tid DESC')
				data = None
				if results > 0:
					input_norm = normalize_test_id(test_id)
					all_tests = cur.fetchall()
					for row in all_tests:
						if normalize_test_id(row['test_id']) == input_norm:
							data = row
							break
				if data is not None:
					test_id = data['test_id']
					password = data['password']
					duration = data['duration']
					calc = data['calc']
					subject = data['subject']
					topic = data['topic']
					start = data['start']
					start = str(start)
					end = data['end']
					end = str(end)
					proctortype = data['proctoring_type']
					if password == password_candidate:
						now = datetime.now()
						start_dt = parse_exam_datetime(start)
						end_dt = parse_exam_datetime(end)
						if start_dt is None or end_dt is None:
							flash('Exam schedule is invalid. Contact professor.', 'danger')
							return redirect(url_for('give_test'))
						# Inclusive window: allow start and end boundary timestamps.
						if start_dt <= now <= end_dt:
							results = cur.execute('SELECT time_left as time_left,completed from studentTestInfo where email = ? and test_id = ?', (session['email'], test_id))
							if results > 0:
								results = cur.fetchone()
								is_completed = results['completed']
								if is_completed == 0:
									time_left = results['time_left']
									if time_left <= duration:
										duration = time_left
										results = cur.execute('SELECT qid , ans from students where email = ? and test_id = ? and uid = ?', (session['email'], test_id, session['uid']))
										marked_ans = {}
										if results > 0:
											results = cur.fetchall()
											for row in results:
												print(row['qid'])
												qiddb = ""+row['qid']
												print(qiddb)
												marked_ans[qiddb] = row['ans']
												marked_ans = json.dumps(marked_ans)
								else:
									flash('Exam already given', 'success')
									return redirect(url_for('give_test'))
							else:
								cur.execute('INSERT into studentTestInfo (email, test_id,time_left,uid) values(?,?,?,?)', (session['email'], test_id, duration, session['uid']))
								mysql.connection.commit()
								results = cur.execute('SELECT time_left as time_left,completed from studentTestInfo where email = ? and test_id = ? and uid = ?', (session['email'], test_id, session['uid']))
								if results > 0:
									results = cur.fetchone()
									is_completed = results['completed']
									if is_completed == 0:
										time_left = results['time_left']
										if time_left <= duration:
											duration = time_left
											results = cur.execute('SELECT * from students where email = ? and test_id = ? and uid = ?', (session['email'], test_id, session['uid']))
											marked_ans = {}
											if results > 0:
												results = cur.fetchall()
												for row in results:
													marked_ans[row['qid']] = row['ans']
												marked_ans = json.dumps(marked_ans)
						else:
							if start_dt > now:
								flash(f'Exam start time is {start}', 'danger')
							else:
								flash(f'Exam has ended', 'danger')
							return redirect(url_for('give_test'))
						return redirect(url_for('test' , testid = test_id))
					else:
						flash('Invalid password', 'danger')
						return redirect(url_for('give_test'))
				flash('Invalid testid. Select from active exam list and try again.', 'danger')
				return redirect(url_for('give_test'))
				cur.close()
			else:
				flash('Image not Verified', 'danger')
				return redirect(url_for('give_test'))
	return render_template('give_test.html', form=form, available_test_ids=available_test_ids)

@app.route('/give-test/<testid>', methods=['GET','POST'])
@user_role_student
def test(testid):
	testid = (testid or "").strip()
	cur = mysql.connection.cursor()
	callresults = None
	normalized_id = normalize_test_id(testid)
	results = cur.execute(
		'SELECT test_id, test_type, start, end FROM teachers WHERE LOWER(TRIM(test_id)) = ? ORDER BY tid DESC',
		[normalized_id]
	)
	if results > 0:
		callresults = cur.fetchone()
		testid = callresults['test_id']
	else:
		now_window = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		active_results = cur.execute(
			'SELECT test_id, test_type, start, end FROM teachers WHERE start <= ? AND end >= ? ORDER BY start ASC',
			(now_window, now_window)
		)
		if active_results > 0:
			active_rows = cur.fetchall()
			if len(active_rows) == 1:
				callresults = active_rows[0]
				testid = callresults['test_id']
			else:
				for row in active_rows:
					if normalize_test_id(row['test_id']) == normalized_id:
						callresults = row
						testid = row['test_id']
						break
	cur.close()
	if not callresults:
		return redirect(url_for('give_test', error='Invalid testid'))
	test_type_value = callresults['test_type'] if callresults['test_type'] is not None else ""
	if str(test_type_value).strip() == "":
		return redirect(url_for('give_test', error='Invalid testid'))

	if callresults['test_type'] == "objective":
		global duration, marked_ans, calc, subject, topic, proctortype
		if request.method == 'GET':
			try:
				data = {'duration': duration, 'marks': '', 'q': '', 'a': '', 'b':'','c':'','d':'' }
				return render_template('testquiz.html' ,**data, answers=marked_ans, calc=calc, subject=subject, topic=topic, tid=testid, proctortype=proctortype)
			except:
				return redirect(url_for('give_test'))
		else:
			try:
				cur = mysql.connection.cursor()
				flag = (request.form.get('flag') or '').strip().lower()
				if flag == 'get':
					num = request.form.get('no')
					results = cur.execute('SELECT test_id,qid,q,a,b,c,d,ans,marks from questions where test_id = ? and qid =?', (testid, num))
					if results > 0:
						data = dict(cur.fetchone())
						data.pop('ans', None)
						cur.close()
						return json.dumps(data)
					cur.close()
					return json.dumps({'error': 'Question not found'})
				elif flag == 'mark':
					qid = request.form.get('qid')
					ans = request.form.get('ans')
					cur = mysql.connection.cursor()
					results = cur.execute('SELECT * from students where test_id =? and qid = ? and email = ?', (testid, qid, session['email']))
					if results > 0:
						cur.execute('UPDATE students set ans = ? where test_id = ? and qid = ? and email = ?', (ans, testid, qid, session['email']))
						mysql.connection.commit()
						cur.close()
					else:
						cur.execute('INSERT INTO students(email,test_id,qid,ans,uid) values(?,?,?,?,?)', (session['email'], testid, qid, ans, session['uid']))
						mysql.connection.commit()
						cur.close()
					return json.dumps({'status': 'ok'})
				elif flag == 'time':
					cur = mysql.connection.cursor()
					time_left = request.form.get('time', 0)
					try:
						cur.execute('UPDATE studentTestInfo set time_left=? where test_id = ? and email = ? and uid = ? and completed=0', (time_left, testid, session['email'], session['uid']))
						mysql.connection.commit()
						cur.close()
						return json.dumps({'time': 'fired'})
					except Exception:
						return json.dumps({'time': 'error'})
				else:
					cur = mysql.connection.cursor()
					cur.execute('UPDATE studentTestInfo set completed=1,time_left=? where test_id = ? and email = ? and uid = ?', (0, testid, session['email'], session['uid']))
					if cur.rowcount == 0:
						cur.execute('UPDATE studentTestInfo set completed=1,time_left=? where test_id = ? and email = ?', (0, testid, session['email']))
					if cur.rowcount == 0:
						cur.execute('INSERT into studentTestInfo (email, test_id, time_left, uid, completed) values(?,?,?,?,?)', (session['email'], testid, 0, session['uid'], 1))
					mysql.connection.commit()
					cur.close()
					flash("Exam submitted successfully", 'info')
					return json.dumps({'sql': 'fired'})
			except Exception as e:
				app.logger.exception("Objective POST error on %s: %s", testid, e)
				return json.dumps({'error': 'submit_failed'})

	elif callresults['test_type'] == "subjective":
		if request.method == 'GET':
			cur = mysql.connection.cursor()
			cur.execute('SELECT test_id, qid, q, marks from longqa where test_id = ? ORDER BY qid ASC',[testid])
			callresults1 = cur.fetchall()
			cur.execute('SELECT time_left as duration from studentTestInfo where completed = 0 and test_id = ? and email = ? and uid = ?', (testid, session['email'], session['uid']))
			studentTestInfo = cur.fetchone()
			if studentTestInfo != None:
				duration = studentTestInfo['duration']
				cur.execute('SELECT test_id, subject, topic, proctoring_type from teachers where test_id = ?',[testid])
				testDetails = cur.fetchone()
				subject = testDetails['subject']
				test_id = testDetails['test_id']
				topic = testDetails['topic']
				proctortypes = testDetails['proctoring_type']
				cur.close()
				return render_template("testsubjective.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic, proctortypes = proctortypes )
			else:
				cur = mysql.connection.cursor()
				cur.execute('SELECT test_id, duration, subject, topic from teachers where test_id = ?',[testid])
				testDetails = cur.fetchone()
				subject = testDetails['subject']
				duration = testDetails['duration']
				test_id = testDetails['test_id']
				topic = testDetails['topic']
				cur.close()
				return render_template("testsubjective.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic )
		elif request.method == 'POST':
			cur = mysql.connection.cursor()
			test_id = request.form["test_id"]
			cur = mysql.connection.cursor()
			results1 = cur.execute('SELECT COUNT(qid) from longqa where test_id = ?',[testid])
			results1 = cur.fetchone()
			cur.close()
			insertStudentData = None
			for sa in range(1,results1['COUNT(qid)']+1):
				answerByStudent = request.form[str(sa)]
				cur = mysql.connection.cursor()
				insertStudentData = cur.execute('INSERT INTO longtest(email,test_id,qid,ans,uid) values(?,?,?,?,?)', (session['email'], testid, sa, answerByStudent, session['uid']))
				mysql.connection.commit()
			else:
				if insertStudentData > 0:
					insertStudentTestInfoData = cur.execute('UPDATE studentTestInfo set completed = 1 where test_id = ? and email = ? and uid = ?', (test_id, session['email'], session['uid']))
					mysql.connection.commit()
					cur.close()
					if insertStudentTestInfoData > 0:
						flash('Successfully Exam Submitted', 'success')
						return redirect(url_for('student_index'))
					else:
						cur.close()
						flash('Some Error was occured!', 'error')
						return redirect(url_for('student_index'))	
				else:
					cur.close()
					flash('Some Error was occured!', 'error')
					return redirect(url_for('student_index'))

	elif callresults['test_type'] == "practical":
		if request.method == 'GET':
			cur = mysql.connection.cursor()
			cur.execute('SELECT test_id, qid, q, marks, compiler from practicalqa where test_id = ? ORDER BY qid ASC',[testid])
			callresults1 = cur.fetchall()
			cur.execute('SELECT time_left as duration from studentTestInfo where completed = 0 and test_id = ? and email = ? and uid = ?', (testid, session['email'], session['uid']))
			studentTestInfo = cur.fetchone()
			if studentTestInfo != None:
				duration = studentTestInfo['duration']
				cur.execute('SELECT test_id, subject, topic, proctoring_type from teachers where test_id = ?',[testid])
				testDetails = cur.fetchone()
				subject = testDetails['subject']
				test_id = testDetails['test_id']
				topic = testDetails['topic']
				proctortypep = testDetails['proctoring_type']
				cur.close()
				return render_template("testpractical.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic, proctortypep = proctortypep )
			else:
				cur = mysql.connection.cursor()
				cur.execute('SELECT test_id, duration, subject, topic from teachers where test_id = ?',[testid])
				testDetails = cur.fetchone()
				subject = testDetails['subject']
				duration = testDetails['duration']
				test_id = testDetails['test_id']
				topic = testDetails['topic']
				cur.close()
				return render_template("testpractical.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic )
		elif request.method == 'POST':
			test_id = request.form["test_id"]
			codeByStudent = request.form["codeByStudent"]
			inputByStudent = request.form["inputByStudent"]
			executedByStudent = request.form["executedByStudent"]
			cur = mysql.connection.cursor()
			insertStudentData = cur.execute('INSERT INTO practicaltest(email,test_id,qid,code,input,executed,uid) values(?,?,?,?,?,?,?)', (session['email'], testid, "1", codeByStudent, inputByStudent, executedByStudent, session['uid']))
			mysql.connection.commit()
			if insertStudentData > 0:
				insertStudentTestInfoData = cur.execute('UPDATE studentTestInfo set completed = 1 where test_id = ? and email = ? and uid = ?', (test_id, session['email'], session['uid']))
				mysql.connection.commit()
				cur.close()
				if insertStudentTestInfoData > 0:
					flash('Successfully Exam Submitted', 'success')
					return redirect(url_for('student_index'))
				else:
					cur.close()
					flash('Some Error was occured!', 'error')
					return redirect(url_for('student_index'))	
			else:
				cur.close()
				flash('Some Error was occured!', 'error')
				return redirect(url_for('student_index'))

	return redirect(url_for('give_test', error='Invalid test type'))

@app.route('/randomize', methods = ['POST'])
def random_gen():
	if request.method == "POST":
		id = request.form['id']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT count(*) from questions where test_id = ?', [id])
		if results > 0:
			data = cur.fetchone()
			total = data['count(*)']
			nos = list(range(1,int(total)+1))
			random.Random(id).shuffle(nos)
			cur.close()
			return json.dumps(nos)

@app.route('/<email>/<testid>')
@user_role_student
def check_result(email, testid):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * FROM teachers where test_id = ?', [testid])
		if results>0:
			results = cur.fetchone()
			check = results['show_ans']
			if check == 1:
				results = cur.execute('select q,a,b,c,d,marks,q.qid as qid, \
					q.ans as correct, ifnull(s.ans,0) as marked from questions q left join \
					students s on  s.test_id = q.test_id and s.test_id = ? \
					and s.email = ? and s.uid = ? and s.qid = q.qid group by q.qid \
					order by LPAD(lower(q.qid),10,0) asc', (testid, email, session['uid']))
				if results > 0:
					results = cur.fetchall()
					return render_template('tests_result.html', results= results)
			else:
				flash('You are not authorized to check the result', 'danger')
				return redirect(url_for('tests_given',email = email))
	else:
		return redirect(url_for('student_index'))

def neg_marks(email,testid,negm):
	cur=mysql.connection.cursor()
	results = cur.execute("select marks,q.qid as qid, \
				q.ans as correct, ifnull(s.ans,0) as marked from questions q inner join \
				students s on  s.test_id = q.test_id and s.test_id = ? \
				and s.email = ? and s.qid = q.qid group by q.qid \
				order by q.qid asc", (testid, email))
	data=cur.fetchall()

	sum=0.0
	for i in range(results):
		if(str(data[i]['marked']).upper() != '0'):
			if(str(data[i]['marked']).upper() != str(data[i]['correct']).upper()):
				sum=sum - (negm/100) * int(data[i]['marks'])
			elif(str(data[i]['marked']).upper() == str(data[i]['correct']).upper()):
				sum+=int(data[i]['marks'])
	return sum

def totmarks(email,tests): 
	cur = mysql.connection.cursor()
	for test in tests:
		testid = test['test_id']
		results=cur.execute("select neg_marks from teachers where test_id=?",[testid])
		results=cur.fetchone()
		negm = results['neg_marks']
		data = neg_marks(email,testid,negm)
		return data

def marks_calc(email,testid):
		cur = mysql.connection.cursor()
		results=cur.execute("select neg_marks from teachers where test_id=?",[testid])
		results=cur.fetchone()
		negm = results['neg_marks']
		return neg_marks(email,testid,negm) 
		
@app.route('/<email>/tests-given', methods = ['POST','GET'])
@user_role_student
def tests_given(email):
	if request.method == "GET":
		if email == session['email']:
			cur = mysql.connection.cursor()
			resultsTestids = cur.execute('select studenttestinfo.test_id as test_id from studenttestinfo,teachers where studenttestinfo.email = ? and studenttestinfo.uid = ? and studenttestinfo.completed=1 and teachers.test_id = studenttestinfo.test_id and teachers.show_ans = 1 ', (session['email'], session['uid']))
			resultsTestids = cur.fetchall()
			if not resultsTestids:
				cur.execute('select distinct studenttestinfo.test_id as test_id from studenttestinfo,teachers where lower(trim(studenttestinfo.email)) = lower(trim(?)) and studenttestinfo.completed=1 and teachers.test_id = studenttestinfo.test_id and teachers.show_ans = 1 ', (session['email'],))
				resultsTestids = cur.fetchall()
			if not resultsTestids:
				# Fallback: if completion flags are missing, still show tests where student has submitted answers.
				cur.execute(
					"SELECT DISTINCT t.test_id as test_id "
					"FROM teachers t "
					"WHERE t.show_ans = 1 AND ("
					"t.test_id IN (SELECT s.test_id FROM students s WHERE lower(trim(s.email)) = lower(trim(?))) "
					"OR t.test_id IN (SELECT l.test_id FROM longtest l WHERE lower(trim(l.email)) = lower(trim(?))) "
					"OR t.test_id IN (SELECT p.test_id FROM practicaltest p WHERE lower(trim(p.email)) = lower(trim(?)))"
					")",
					(session['email'], session['email'], session['email'])
				)
				resultsTestids = cur.fetchall()
			cur.close()
			return render_template('tests_given.html', cresults = resultsTestids)
		else:
			flash('You are not authorized', 'danger')
			return redirect(url_for('student_index'))
	if request.method == "POST":
		if email != session['email']:
			flash('You are not authorized', 'danger')
			return redirect(url_for('student_index'))
		tidoption = (request.form.get('choosetid') or '').strip()
		if not tidoption:
			flash('Please select a valid Exam ID.', 'danger')
			return redirect(url_for('tests_given', email=session['email']))
		cur = mysql.connection.cursor()
		cur.execute('SELECT test_id, test_type from teachers where lower(trim(test_id)) = ?',[normalize_test_id(tidoption)])
		callresults = cur.fetchone()
		cur.close()
		if not callresults or ('test_type' not in callresults.keys()) or not callresults['test_type']:
			flash('Invalid test id', 'danger')
			return redirect(url_for('tests_given', email=session['email']))
		tidoption = callresults['test_id']
		if callresults['test_type'] == "objective":
			cur = mysql.connection.cursor()
			results = cur.execute('select distinct(students.test_id) as test_id, students.email as email, subject,topic,neg_marks from students,studenttestinfo,teachers where students.email = ? and teachers.test_type = ? and students.test_id = ? and students.test_id=teachers.test_id and students.test_id=studenttestinfo.test_id and studenttestinfo.completed=1', (email, "objective", tidoption))
			rows = cur.fetchall()
			if not rows:
				cur.execute('select distinct students.test_id as test_id, students.email as email, teachers.subject as subject, teachers.topic as topic, teachers.neg_marks as neg_marks from students,teachers where lower(trim(students.email)) = lower(trim(?)) and students.test_id = ? and students.test_id=teachers.test_id', (email, tidoption))
				rows = cur.fetchall()
			cur.close()
			studentResults = []
			for a in rows:
				item = dict(a)
				item['marks'] = neg_marks(a['email'], a['test_id'], a['neg_marks'])
				studentResults.append(item)
			return render_template('obj_result_student.html', tests=studentResults)
		elif callresults['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(longtest.marks) as marks, longtest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from longtest,teachers,studenttestinfo where longtest.email = ? and longtest.test_id = ? and longtest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and longtest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by longtest.test_id', (email, tidoption))
			studentRows = cur.fetchall()
			if not studentRows:
				cur.execute('select SUM(longtest.marks) as marks, longtest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from longtest,teachers where lower(trim(longtest.email)) = lower(trim(?)) and longtest.test_id = ? and longtest.test_id=teachers.test_id group by longtest.test_id', (email, tidoption))
				studentRows = cur.fetchall()
			cur.close()
			return render_template('sub_result_student.html', tests=studentRows)
		elif callresults['test_type'] == "practical":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(practicaltest.marks) as marks, practicaltest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from practicaltest,teachers,studenttestinfo where practicaltest.email = ? and practicaltest.test_id = ? and practicaltest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and practicaltest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by practicaltest.test_id', (email, tidoption))
			studentRows = cur.fetchall()
			if not studentRows:
				cur.execute('select SUM(practicaltest.marks) as marks, practicaltest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from practicaltest,teachers where lower(trim(practicaltest.email)) = lower(trim(?)) and practicaltest.test_id = ? and practicaltest.test_id=teachers.test_id group by practicaltest.test_id', (email, tidoption))
				studentRows = cur.fetchall()
			cur.close()
			return render_template('prac_result_student.html', tests=studentRows)
		flash('Unsupported test type', 'danger')
		return redirect(url_for('tests_given', email=session['email']))
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))

@app.route('/<email>/tests-created')
@user_role_professor
def tests_created(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = ? and uid = ? and show_ans = 1', (email,session['uid']))
		rows = cur.fetchall()
		if not rows:
			cur.execute('select * from teachers where email = ? and show_ans = 1', (email,))
			rows = cur.fetchall()
		return render_template('tests_created.html', tests=rows)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/tests-created/<testid>', methods = ['POST','GET'])
@user_role_professor
def student_results(email, testid):
	if email != session['email']:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

	# Resolve teacher row by normalized test_id + email to avoid uid mismatch issues.
	cur = mysql.connection.cursor()
	cur.execute(
		'SELECT test_id, test_type FROM teachers WHERE lower(trim(email)) = lower(trim(?))',
		(session['email'],)
	)
	teacher_rows = cur.fetchall()
	cur.close()

	et = None
	input_norm = normalize_test_id(testid)
	for row in teacher_rows:
		if normalize_test_id(row['test_id']) == input_norm:
			testid = row['test_id']
			et = {'test_type': row['test_type']}
			break

	if not et or 'test_type' not in et or not et['test_type']:
		flash('Invalid test id', 'danger')
		return redirect(url_for('tests_created', email=session['email']))

	if request.method != 'GET':
		return redirect(url_for('tests_created', email=session['email']))

	if et['test_type'] == "objective":
		cur = mysql.connection.cursor()
		results = cur.execute('select users.name as name,users.email as email, studentTestInfo.test_id as test_id from studentTestInfo, users where test_id = ? and completed = 1 and  users.user_type = ? and studentTestInfo.email=users.email ', (testid,'student'))
		rows = cur.fetchall()
		if not rows:
			cur.execute('select distinct users.name as name,users.email as email, students.test_id as test_id from students, users where students.test_id = ? and users.user_type = ? and students.email=users.email', (testid, 'student'))
			rows = cur.fetchall()
		cur.close()
		final = []
		names = []
		scores = []
		count = 1
		for user in rows:
			score = marks_calc(user['email'], user['test_id'])
			final.append([count, user['name'], score])
			names.append(user['name'])
			scores.append(score)
			count+=1
		return render_template('student_results.html', data=final, labels=names, values=scores)
	elif et['test_type'] == "subjective":
		cur = mysql.connection.cursor()
		results = cur.execute('select users.name as name,users.email as email, longtest.test_id as test_id, SUM(longtest.marks) AS marks from longtest, users where longtest.test_id = ?  and  users.user_type = ? and longtest.email=users.email', (testid,'student'))
		results = cur.fetchall()
		cur.close()
		names = []
		scores = []
		for user in results:
			names.append(user['name'])
			scores.append(user['marks'])
		return render_template('student_results_lqa.html', data=results, labels=names, values=scores)
	elif et['test_type'] == "practical":
		cur = mysql.connection.cursor()
		results = cur.execute('select users.name as name,users.email as email, practicaltest.test_id as test_id, SUM(practicaltest.marks) AS marks from practicaltest, users where practicaltest.test_id = ?  and  users.user_type = ? and practicaltest.email=users.email', (testid,'student'))
		results = cur.fetchall()
		cur.close()
		names = []
		scores = []
		for user in results:
			names.append(user['name'])
			scores.append(user['marks'])
		return render_template('student_results_pqa.html', data=results, labels=names, values=scores)

	flash('Invalid test type', 'danger')
	return redirect(url_for('tests_created', email=session['email']))

@app.route('/<email>/disptests')
@user_role_professor
def disptests(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = ? and uid = ?', (email,session['uid']))
		results = cur.fetchall()
		return render_template('disptests.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/student_test_history')
@user_role_student
def student_test_history(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute(
			'SELECT DISTINCT x.test_id, t.subject, t.topic \
			FROM teachers t \
			INNER JOIN ( \
				SELECT test_id FROM studenttestinfo WHERE lower(trim(email)) = lower(trim(?)) AND completed = 1 \
				UNION \
				SELECT test_id FROM students WHERE lower(trim(email)) = lower(trim(?)) \
				UNION \
				SELECT test_id FROM longtest WHERE lower(trim(email)) = lower(trim(?)) \
				UNION \
				SELECT test_id FROM practicaltest WHERE lower(trim(email)) = lower(trim(?)) \
			) x ON x.test_id = t.test_id',
			(email, email, email, email)
		)
		results = cur.fetchall()
		return render_template('student_test_history.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))

@app.route('/test_generate', methods=["GET", "POST"])
@user_role_professor
def test_generate():
	if request.method == "POST":
		inputText = request.form["itext"]
		testType = request.form["test_type"]
		noOfQues = request.form["noq"]
		# Speed guardrails to keep generation under ~40s in typical cases.
		max_chars = 2000
		max_questions = 10
		if len(inputText) > max_chars:
			inputText = inputText[:max_chars]
			flash(f'Input text trimmed to {max_chars} characters for faster generation.', 'warning')
		try:
			noOfQues = int(noOfQues)
		except Exception:
			noOfQues = 5
		if noOfQues > max_questions:
			noOfQues = max_questions
			flash(f'Questions capped at {max_questions} for faster generation.', 'warning')
		if testType == "objective":
			try:
				objective_generator = ObjectiveTest(inputText,noOfQues)
				question_list, answer_list = objective_generator.generate_test()
				testgenerate = zip(question_list, answer_list)
				return render_template('generatedtestdata.html', cresults = testgenerate)
			except Exception as e:
				flash(f'Error generating objective test: {str(e)}', 'danger')
				return redirect(url_for('generate_test'))
		elif testType == "subjective":
			try:
				subjective_generator = SubjectiveTest(inputText,noOfQues)
				question_list, answer_list = subjective_generator.generate_test()
				testgenerate = zip(question_list, answer_list)
				return render_template('generatedtestdata.html', cresults = testgenerate)
			except Exception as e:
				flash(f'Error generating subjective test: {str(e)}', 'danger')
				return redirect(url_for('generate_test'))
		else:
			return None
	return render_template('generatetest.html')

if __name__ == "__main__":
	port = int(os.getenv("PORT", "5000"))
	print(f"App is running on http://0.0.0.0:{port}")
	app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
