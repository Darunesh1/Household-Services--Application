from flask import Flask, url_for, render_template,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,EmailField,SelectField
from wtforms.validators import InputRequired,Length,ValidationError,Email,EqualTo,Regexp
from flask_bcrypt import Bcrypt
from datetime import datetime
from sqlalchemy import func



app = Flask(__name__)
# db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'fghjhj+fddbfb151515331'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)    
    username = db.Column(db.String(30), nullable=False,unique=True)
    password = db.Column(db.String(80), nullable=False)
    email=db.Column(db.String(20),nullable=False,unique=True)
    mobile=db.Column(db.String(15),nullable=False)
    role=db.Column(db.String(15),nullable=False)
    date_added=db.Column(db.DateTime,default=func.now())
    
    
    
    def __repr__(self):
        return '<Name %r>' % self.name
    
    def is_admin(self):
        return self.role.lower() == "admin"

    def is_influencer(self):
        return self.role.lower() == "influencer"
    
    def is_sponsor(self):
        return self.role.lower() == "sponsor"

# forms
class RegisterForm(FlaskForm):
    
    name = StringField(
        'Name',
        validators=[InputRequired(), Length(min=4, max=30)],
        render_kw={"placeholder": "Enter your Name"}
    ) 
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=4, max=25)],
        render_kw={"placeholder": "Username"}
    )
    email = EmailField(
        'Email',
        validators=[InputRequired(), Email(), Length(min=6, max=35)],
        render_kw={"placeholder": "Email"}
    )
    mobile = StringField(
        'Mobile Number',
        validators=[
            InputRequired(),
            Length(min=10, max=10),
            Regexp(r'^\d{10}$', message="Invalid mobile number format.")
        ],
        render_kw={"placeholder": "Mobile Number"}
    )
    password = PasswordField(
        'Password',
        validators=[InputRequired(), Length(min=6, max=20)],
        render_kw={"placeholder": "Password"}
    )
    repassword = PasswordField(
        'Re-Enter Password',
        validators=[
            InputRequired(),
            Length(min=6, max=20),
            EqualTo('password', message='Passwords must match.')
        ],
        render_kw={"placeholder": "Re-Enter Password"}
    )
    role = SelectField(
        'Role',
        choices=[('influencer', 'Influencer'), ('sponsor', 'Sponsor')],
        validators=[InputRequired()],
        render_kw={"placeholder": "Select your role"}
    )
    
    
    submit=SubmitField("Register")
    
    
    def validate_username(self,username):
        user=User.query.filter_by(username=username.data).first()
        
        if  user:
            raise ValidationError('Username already exists.Please choose a different one.')
        
    def validate_password(self, password):
        if password.data != self.repassword.data:
            raise ValidationError('Passwords do not match.')
 
 
@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(name=form.name.data,username=form.username.data, password=hashed_password, email=form.email.data, mobile=form.mobile.data, role=form.role.data)

        db.session.add(new_user)
        db.session.commit()
        flash("Account  created successfully", "success")

        return redirect(url_for('login'))
    
    # if form.username.errors:
    #     flash('Username already exists. Please choose a different one.', 'warning')
    #     # return redirect(url_for('register'))
    # if form.password.errors:
    #     flash('Passwords does not match', 'warning')
    #     # return redirect(url_for('register'))
    if form.errors:
        for error_msg in form.errors.values():
            flash(error_msg[0], 'danger')
        
    return render_template('register.html',form=form)
    
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=25)],render_kw={"placeholder":"Username"})
    
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    
    
    submit=SubmitField("Login")

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                flash("you have logged in!","info")
                return redirect(url_for("dashboard"))            
        flash("Incorrect username or password","warning") 
        return redirect(url_for('login')) 
    return render_template('login.html',form=form)


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You have logged out!","info")
    return redirect(url_for('login'))


@app.route('/')
def hello_world():
    return render_template('base.html')


@app.route('/about/<username>')
def about_page(username):
    return f'<h1>This is an about page of {username}</h1>'

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/adduser',methods=['GET','POST'])
def  adduser():
    form=RegisterForm()
    return render_template('adduser.html',form=form)



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
