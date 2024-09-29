from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from pymongo import MongoClient
import bcrypt
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key'

client = MongoClient("mongodb://localhost:27017/")
db = client.dhtslogin
users = db.login

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

def encrypt(password: str) -> str:
    try:
        if len(password) < 8 or len(password) > 73:
            raise ValueError
        number = string.digits
        white_space = string.whitespace
        lower_case = string.ascii_lowercase
        upper_case = string.ascii_uppercase
        special_char = string.punctuation

        NUM_FLAG, LOWER_FLAG, UPPER_FLAG, SPECIAL_CHAR_FLAG = False, False, False, False
        for i in password:
            if i in lower_case:
                LOWER_FLAG = True
                continue
            elif i in upper_case:
                UPPER_FLAG = True
                continue
            elif i in number:
                NUM_FLAG = True
                continue
            elif i in special_char:
                SPECIAL_CHAR_FLAG = True
                continue
            if i in white_space:
                raise AttributeError

        if not NUM_FLAG:
            raise Exception("Password must contain at least one number")
        elif not LOWER_FLAG:
            raise Exception("Password must contain at least one lowercase letter")
        elif not UPPER_FLAG:
            raise Exception("Password must contain at least one uppercase letter")
        elif not SPECIAL_CHAR_FLAG:
            raise Exception("Password must contain at least one special character")
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            return hashed_password.decode('utf-8')
    except ValueError:
        print("Password must be at least 8 characters and at most 72 characters long")
        return ""
    except AttributeError:
        print("Password must not contain white space characters")
        return ""

def verifier(password: str, hash_string: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hash_string.encode('utf-8'))


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users.find_one({'username': form.username.data})
        if user and verifier(form.password.data, user['password']):
            session['username'] = form.username.data
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = users.find_one({'username': form.username.data})
        if existing_user:
            flash('User already exists!', 'danger')
        else:
            hashed_password = encrypt(form.password.data)
            if hashed_password:  # Ensure the password passed all checks
                users.insert_one({'username': form.username.data, 'password': hashed_password})
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Registration failed. Password does not meet the requirements.', 'danger')
    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
