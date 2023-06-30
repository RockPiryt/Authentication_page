from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap5



app = Flask(__name__)
bootstrap = Bootstrap5(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose' #Session
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()


#----------------------------Flask- Login
#Create login_manager class
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

class RegisterForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired()])
    password = StringField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Sing me up")

class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password = StringField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Let me in.")

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    '''Register new users'''

    register_form = RegisterForm()
    if register_form.validate_on_submit():
        form_name = register_form.name.data 
        form_email = register_form.email.data 
        form_password = register_form.password.data
        #Hash and salt password
        hash_salted_password = generate_password_hash(password=form_password, method="pbkdf2:sha256", salt_length=8)
        only_password= hash_salted_password.split("$")[2]
        user=User(
            name=form_name, 
            email=form_email,
            password=only_password,
        )
        db.session.add(user) 
        db.session.commit()

        return redirect(url_for("secrets", html_user_name=user.name))
    return render_template("register.html", html_register_form=register_form)


@app.route('/login')
def login():
    '''Login existing users'''

    #Create login_form
    login_form=LoginForm()

    #Get data from login_form
    if login_form.validate_on_submit():
        login_form_email = login_form.email.data
        login_form_password = login_form.password.data

        #Find user in database by email, which is unique
        user = User.query.filter_by(email=login_form_email).first()

        return redirect(url_for("secrets"))
    return render_template("login.html", html_login_form=login_form)


@app.route('/secrets')
def secrets():

    # Get information from request (redirecting from register)
    current_user_name= request.args.get("html_user_name")
    # Search user in database using name from request
    current_user_object = User.query.filter_by(name=current_user_name).first()

    return render_template("secrets.html", html_current_user_name=current_user_name, html_current_user_object=current_user_object)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    return send_from_directory(directory='static', path='files/photo_cinema.jpg', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
