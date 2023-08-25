from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, FileField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap5
import secrets

from flask_wtf.file import FileField, FileRequired, FileAllowed
import os
from werkzeug.utils import secure_filename


# #------------------Upload files settings
UPLOAD_FOLDER = '/static/files/user_files/'
# ALLOWED_EXTENSIONS = 'png', 'jpg', 'jpeg'

#------------------Application settings
application = Flask(__name__)

application.config['SECRET_KEY'] = secrets.token_hex(32)# Session
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'pulse'
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
application.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000#max file size 16mb

bootstrap = Bootstrap5(application)
db = SQLAlchemy(application)
application.app_context().push()

# -------------------Flask- Login
# Create login_manager class
login_manager = LoginManager()
login_manager.init_app(application)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# # Save file in db
# class Upload(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     filename = db.Column(db.String(200))
#     data =db.Column(db.LArgeBinary)


if db:
    pass
else:
    db.create_all()


class RegisterForm(FlaskForm):
    name = StringField(label=" ", validators=[DataRequired()], render_kw={"placeholder":"Name"})
    email = EmailField(label=" ", validators=[DataRequired()], render_kw={"placeholder":"Email"})
    password = PasswordField(label=" ", validators=[DataRequired()], render_kw={"placeholder":"Password"})
    submit = SubmitField(label="Sing up")


class LoginForm(FlaskForm):
    email = EmailField(label=" ", validators=[DataRequired()], render_kw={"placeholder":"Email"})
    password = PasswordField(label=" ", validators=[DataRequired()], render_kw={"placeholder":"Password"})
    submit = SubmitField(label="Log in")

class UploadForm(FlaskForm):
    photo = FileField(label='User Photo', validators=[FileRequired(), FileAllowed(['png', 'jpg', 'jpeg'], 'Images only!')])
    submit = SubmitField(label="Upload photo")


@application.route('/')
def home():
    show =" "
    return render_template("index.html", html_show=show)


@application.route('/register', methods=["GET", "POST"])
def register():
    '''Register new users'''

    # Create register_form
    register_form = RegisterForm()

    # Get data from register_form
    if register_form.validate_on_submit():
        form_name = register_form.name.data
        form_email = register_form.email.data
        form_password = register_form.password.data

        #Check if user exists in database
        existing_user =  User.query.filter_by(email=form_email).first()
        if existing_user:
            flash("You have already signed up with that email, log in please! ")
            return redirect(url_for("login"))

        # Hash and salt password
        hash_salted_password = generate_password_hash(
            password=form_password, method="pbkdf2:sha256", salt_length=8)
        new_user = User(
            name=form_name,
            email=form_email,
            password=hash_salted_password,
        )
        # Add user info to db
        db.session.add(new_user)
        db.session.commit()

        # Login user after registration
        login_user(new_user)

        return redirect(url_for("secrets"))
        # return redirect(url_for("secrets", html_user_name=new_user.name))#second method
    return render_template("register_flaskform.html", html_register_form=register_form)


@application.route('/login', methods=["GET", "POST"])
def login():
    '''Login existing users'''

    # Create login_form
    login_form = LoginForm()

    # Get data from login_form
    if login_form.validate_on_submit():
        login_form_email = login_form.email.data
        login_form_password = login_form.password.data

        # Find user in database by email, which is unique
        user = User.query.filter_by(email=login_form_email).first()

        #User with that email doesn't exist
        if not user:
            flash("That email does not exist. Please try again.")
            return redirect(url_for("login"))
        # Password incorrect
        if not check_password_hash(user.password, login_form_password):
            flash("Password incorrect. Please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("secrets"))
        
        # # Check password from database against entered password
        # if check_password_hash(user.password, login_form_password):
        #     login_user(user)
        #     return redirect(url_for("secrets"))
    return render_template("login_flaskform.html", html_login_form=login_form)


@application.route('/secrets')
@login_required
def secrets():
    '''Show file to download'''
    flash("Logged in successfully")
    return render_template("secrets.html", html_current_user=current_user, logged_in=current_user.is_authenticated)


@application.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@application.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', path='files/download/photo_cinema.jpg', as_attachment=True)

@application.route('/upload-photo', methods=["GET", "POST"])
@login_required
def upload_photo():
    '''Upload user photo'''

    upload_form = UploadForm()
    if upload_form.validate_on_submit():
        # Get file from upload_form
        user_file = upload_form.photo.data
        # Secure filename
        secure_user_file = secure_filename(user_file.filename)
        #Save file
        basedir = os.path.abspath(os.path.dirname(__file__))#app folder
        # new_basedir = basedir.replace('\\', '/')
        # # print(basedir)
        filedir = os.path.join(basedir + application.config['UPLOAD_FOLDER'], secure_user_file)#file folder+ file to save
        user_file.save(filedir)
        # user_file.save('static/files/upload/' + secure_user_file)
        
        flash('Photo uploaded successfully.')
        img = application.config['UPLOAD_FOLDER']+ secure_user_file
        return render_template("upload_photo.html", img=img, html_upload_form=upload_form)
        # return redirect(url_for('static', filename='files/user_files/' + user_file.filename), code=301)# To see uploaded img
    return render_template("upload_photo.html", html_upload_form=upload_form)


@application.route('/display/<filedir>')
def display_image(filedir):
	#print('display_image filename: ' + filename)
	return render_template()


if __name__ == "__main__":
    application.run(debug=True)
















# #------------------------Route without login_required - use request method
# @app.route('/secrets')
# def secrets():

#     # Get information from request (redirecting from register)
#     user_name = request.args.get("html_user_name")
#     # Search user in database using name from request
#     user_object = User.query.filter_by(name=user_name).first()
#     user_object_email = user_object.email

#     return render_template("secrets.html",html_object_email=user_object_email)