from flask import Flask, abort, url_for, render_template,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user,login_user,LoginManager,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField,PasswordField,SubmitField,EmailField,SelectField, TextAreaField
from wtforms.validators import InputRequired,Length,ValidationError,Email,EqualTo,Regexp
from flask_bcrypt import Bcrypt
from sqlalchemy import func
from wtforms.widgets import TextArea



app = Flask(__name__)
# db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'fghjhj+fddbfb151515331'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Model fro user
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)    
    password = db.Column(db.String(80), nullable=False)
    email=db.Column(db.String(20),nullable=False,unique=True)
    address=db.Column(db.Text, nullable=False)
    mobile=db.Column(db.String(15),nullable=False)
    role=db.Column(db.String(15),nullable=False)
    status=db.Column(db.Boolean,default=False)    
    date_added=db.Column(db.DateTime,default=func.now())
    
    
    def __repr__(self):
        return '<Name %r>' % self.name
    
class FlaggedUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer,nullable=False)
    description = db.Column(db.Text, nullable=False)    
    date_added = db.Column(db.DateTime, nullable=False, default=func.now())
    
# model for services
class Services(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False,unique=True)
    description = db.Column(db.Text, nullable=False)    
    base_price=db.Column(db.Integer, nullable=False)    
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    
class ServicesRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id=db.Column(db.Integer,nullable=False)
    professional_id=db.Column(db.Integer,nullable=False)
    review_id=db.Column(db.Integer,nullable=False)
    description = db.Column(db.Text, nullable=False)    
    status=db.Column(db.Boolean,default=False)
    service_id=db.Column(db.Integer,nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    
# experience model fro professional
class Professional(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer,nullable=False)
    status=db.Column(db.Boolean,default=False)
    service_id=db.Column(db.Integer,nullable=False)
    experience=db.Column(db.Integer, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    
class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    rating=db.Column(db.Integer, nullable=False)
    service_id=db.Column(db.Integer,nullable=False)
    customer_id=db.Column(db.Integer,nullable=False)
    professional_id=db.Column(db.Integer,nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())

# forms
class RegisterForm(FlaskForm):
    
    name = StringField(
        'Name',
        validators=[InputRequired(), Length(min=4, max=30)],
       
    ) 
    
    email = EmailField(
        'Email',
        validators=[InputRequired(), Email(), Length(min=6, max=35)],
        
    )
    mobile = StringField(
        'Mobile Number',
        validators=[
            InputRequired(),
            Length(min=10, max=10),
            Regexp(r'^\d{10}$', message="Invalid mobile number format.")
        ],
        
    )
    password = PasswordField(
        'Password',
        validators=[InputRequired(), Length(min=6, max=20)],
       
    )
    repassword = PasswordField(
        'Re-Enter Password',
        validators=[
            InputRequired(),
            Length(min=6, max=20),
            EqualTo('password', message='Passwords must match.')
        ],
        
    )
    role = SelectField(
        'Role',
        choices=[( 'Customer'), ( 'Professional')],
        validators=[InputRequired()],
        
    )
    address = TextAreaField(
        'Address',
        validators=[InputRequired()],
        
    )     
    
    submit=SubmitField("Register")
    
    
    def validate_email(self,email):
        user=User.query.filter_by(email=email.data).first()
        
        if  user:
            raise ValidationError('email already exists.Please choose a different one.')
        
    def validate_password(self, password):
        if password.data != self.repassword.data:
            raise ValidationError('Passwords do not match.')

class ServiceFrom(FlaskForm):  
    
    title=StringField(
        validators=[InputRequired(),Length(min=4,max=80)],render_kw={"placeholder":"Title"}
        )
    
    description=TextAreaField(
        validators=[InputRequired(),Length(min=4)],render_kw={"placeholder":"Content"}
        )
    
    base_price=IntegerField(
        validators=[InputRequired()],render_kw={"placeholder":"Base Price"}
    )  
    
    submit=SubmitField("Post")
    
    def validate_title(self,title):
        service=Services.query.filter_by(title=title.data).first()
        
        if  service:
            raise ValidationError('Service already exists.Please choose a different one.')

class EditServiceFrom(FlaskForm):
    def __init__(self, service, *args, **kwargs):
        super(EditServiceFrom, self).__init__(*args, **kwargs)   
        self.service = service
        
        
    title=StringField(
        validators=[InputRequired(),Length(min=4,max=80)],render_kw={"placeholder":"Title"}
        )
    
    description=TextAreaField(
        validators=[InputRequired(),Length(min=4)],render_kw={"placeholder":"Content"}
        )
    
    base_price=IntegerField(
        validators=[InputRequired()],render_kw={"placeholder":"Base Price"}
    )  
    
    submit=SubmitField("Post")
    
    def validate_email(self, title):
        if title.data != self.service.title:
            service = Services.query.filter_by(title=title.data).first()
            if service:
                raise ValidationError("Title already exists. Please choose a different one.")
    
    
    
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=25)],render_kw={"placeholder":"Username"})
    
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    
    
    submit=SubmitField("Login")
    
class EditUserForm(FlaskForm):
    def __init__(self, current_user, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)       
        self.current_user = current_user
    
    name = StringField(
        'Name',
        validators=[InputRequired(), Length(min=4, max=30)],
       
    ) 
    email = EmailField(
        'Email',
        validators=[InputRequired(), Email(), Length(min=6, max=35)],
        
    )
    mobile = StringField(
        'Mobile Number',
        validators=[
            InputRequired(),
            Length(min=10, max=10),
            Regexp(r'^\d{10}$', message="Invalid mobile number format.")
        ],
        
    ) 
    address = TextAreaField(
        'Address',
        validators=[InputRequired()],
        
    )
    
    
    submit=SubmitField("Register")  
    
   
    def validate_email(self, email):
        if email.data != self.current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exists. Please choose a different one.")
 
 

@app.route('/register',methods=['GET','POST'])
def register():    
    form=RegisterForm()
    title="Sign Up"
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(
            name=form.name.data,
            password=hashed_password, 
            email=form.email.data, 
            mobile=form.mobile.data, 
            address=form.address.data,
            role=form.role.data
            )

        db.session.add(new_user)
        db.session.commit()
        flash("Account  created successfully", "success")

        return redirect(url_for('login'))
    
   
    if form.errors:
        for error_msg in form.errors.values():
            flash(error_msg[0], 'danger')
        
    return render_template('register.html',form=form,title=title)

    
# Add Post Page
@app.route('/add-service',methods=['GET','POST'])
@login_required
def add_service(): 
    if current_user.id != 0:
        abort(403)   
    form=ServiceFrom()
    title="Add Service"
    
    if form.validate_on_submit():
        new_service=Services(
            title=form.title.data,
            description=form.description.data,
            base_price=form.base_price.data
            )

        db.session.add(new_service)
        db.session.commit()
        flash("Service created successfully", "success")

        return redirect(url_for('show_services'))
    
   
    if form.errors:
        for error_msg in form.errors.values():
            flash(error_msg[0], 'danger')
        
    return render_template('add_service.html',form=form,title=title)
           
 
#  show posts
@app.route('/services')
def show_services():
    services=Services.query.order_by(Services.date_posted.desc()).all()
    
    return render_template('show_services.html',services=services)
    
# individual service pages
@app.route('/service/<int:id>') 
def service(id):
    service=Services.query.get_or_404(id)
    return render_template('service.html',service=service)

# edit service
@app.route('/service/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_service(id):
    if current_user.id != 0:
        abort(403)
    title="Edit Service"
    service=Services.query.get_or_404(id)
    form = EditServiceFrom(service)
    
    if form.validate_on_submit():
        service.title=form.title.data
        service.description=form.description.data
        service.base_price=form.base_price.data
        
        db.session.add(service)
        db.session.commit()
        flash("Service updated successfully", "success")

        return redirect(url_for('service',id=service.id))
    
    form.title.data=service.title
    form.description.data=service.description
    form.base_price.data=service.base_price
    
    return render_template('add_service.html',form=form,title=title)
        
    

# delete service
@app.route('/service/delete/<int:id>',methods=['POST','GET'])
@login_required
def delete_post(id):
    service=Services.query.get_or_404(id)
    db.session.delete(service)
    db.session.commit()
    flash(f"{service.title} has been deleted","danger")
    return redirect(url_for('show_services'))
        
        
        

# login logic
@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(
            email=form.username.data
            ).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                flash("you have logged in!","info")
                return redirect(url_for("dashboard"))            
        flash("Incorrect username or password","warning") 
        return redirect(url_for('login')) 
    return render_template('login.html',form=form)


# logout
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
    return render_template('dashboard.html',user=current_user)

@app.route('/adduser',methods=['GET','POST'])
@login_required
def  add_user():
    if current_user.id != 0:
        abort(403)    
    form=RegisterForm()
    title="Add User"
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(
            name=form.name.data,
            password=hashed_password, 
            email=form.email.data, 
            mobile=form.mobile.data, 
            address=form.address.data,
            role=form.role.data
            )
        
        db.session.add(new_user)
        db.session.commit()
        flash("user added successfully", "success")
        
        return redirect(url_for('login'))
    
    return render_template('register.html',form=form,title=title)

# to display the users
@app.route('/users')
@login_required
def users():
    users=User.query.order_by(User.date_added.desc()).all()
    return render_template('users.html',users=users)

    
    
# detele account
@app.route('/user/delete/<int:id>',methods=['POST','GET'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"{user.name} has been deleted","danger")
        return redirect(url_for('login'))
        
    return redirect(url_for('users'))

# edit user details
@app.route('/user/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_user(id):
    user=User.query.get_or_404(id)
    form=EditUserForm(current_user=current_user)
    
    if form.validate_on_submit():
        user.name=form.name.data
        user.email=form.email.data
        user.mobile=form.mobile.data
        user.address=form.address.data                
          
                    
        db.session.add(user)
        db.session.commit()
        flash(f"{user.name} has been updated","success")
        
        return redirect(url_for('dashboard'))
    
    form.name.data=user.name   
    form.email.data=user.email
    form.mobile.data=user.mobile
    form.address.data=user.address 
        
    
    if form.errors:
        for error_msg in form.errors.values():
            flash(error_msg[0], 'danger')
    
    return render_template('edit_user.html',form=form,user=user)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
