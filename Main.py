from flask import Flask, url_for, render_template,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user,login_user,LoginManager,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,EmailField,SelectField, TextAreaField
from wtforms.validators import InputRequired,Length,ValidationError,Email,EqualTo,Regexp
from flask_bcrypt import Bcrypt
from sqlalchemy import func
from wtforms.widgets import TextArea



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
       
    ) 
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=4, max=25)],
        
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
        choices=[( 'Influencer'), ( 'Sponsor')],
        validators=[InputRequired()],
        
    )
     
    
    submit=SubmitField("Register")
    
    
    def validate_username(self,username):
        user=User.query.filter_by(username=username.data).first()
        
        if  user:
            raise ValidationError('Username already exists.Please choose a different one.')
    def validate_email(self,email):
        user=User.query.filter_by(email=email.data).first()
        
        if  user:
            raise ValidationError('email already exists.Please choose a different one.')
        
    def validate_password(self, password):
        if password.data != self.repassword.data:
            raise ValidationError('Passwords do not match.')
 
 

@app.route('/register',methods=['GET','POST'])
def register():    
    form=RegisterForm()
    title="Sign Up"
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(
            name=form.name.data,
            username=form.username.data, password=hashed_password, 
            email=form.email.data, 
            mobile=form.mobile.data, 
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
#  post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author=db.Column(db.String(20),nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    slug=db.Column(db.String(20),unique=True)
    
    
    
class PostFrom(FlaskForm):
    title=StringField(
        validators=[InputRequired(),Length(min=4,max=80)],render_kw={"placeholder":"Title"}
        )
    
    content=TextAreaField(
        validators=[InputRequired(),Length(min=4)],render_kw={"placeholder":"Content"}
        )
    
    author=StringField(
        validators=[InputRequired()],render_kw={"placeholder":"Author"}
        )
    
    slug=StringField(
        validators=[InputRequired()],render_kw={"placeholder":"Slug"}
        )
    
    
    
    
    submit=SubmitField("Post")
    
    
# Add Post Page
@app.route('/add-post',methods=['GET','POST'])
@login_required
def add_post():
    form=PostFrom()
    title="Add Post"
    
    if form.validate_on_submit():
        post=Posts(
            title=form.title.data,
            content=form.content.data,
            author=form.author.data,
            slug=form.slug.data
            )
        
        form.title.data=''
        form.content.data=''
        form.author.data=''
        form.slug.data=''
        
        db.session.add(post)
        db.session.commit()
        
        flash("Post has been created","success")
        
        
    
    return render_template('add_posts.html',form=form,title=title)
           
 
#  show posts
@app.route('/posts')
def posts():
    
    posts=Posts.query.order_by(Posts.date_posted.desc()).all()
    return render_template('posts.html',posts=posts)

# individual service pages
@app.route('/posts/<int:id>') 
def post(id):
    post=Posts.query.get_or_404(id)
    return render_template('post.html',post=post)

# edit posts
@app.route('/posts/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_post(id):
    post=Posts.query.get_or_404(id)
    form=PostFrom()
    title="Edit Post"
    
    if form.validate_on_submit():
        post.title=form.title.data
        post.content=form.content.data
        post.author=form.author.data
        post.slug=form.slug.data
        
        db.session.add(post)
        db.session.commit()
        flash(f"{post.title} has been updated","success")
        
        return redirect(url_for('post',id=post.id))
    
    form.title.data=post.title
    form.content.data=post.content
    form.author.data=post.author
    form.slug.data=post.slug
    return render_template('add_posts.html',form=form,title=title)

# delete posts
@app.route('/posts/delete/<int:id>',methods=['POST','GET'])
@login_required
def delete_post(id):
    post=Posts.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash(f"{post.title} has been deleted","danger")
    return redirect(url_for('posts'))
        
        
        
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=25)],render_kw={"placeholder":"Username"})
    
    password=PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    
    
    submit=SubmitField("Login")

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(
            username=form.username.data
            ).first()
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
    return render_template('dashboard.html',user=current_user)

@app.route('/adduser',methods=['GET','POST'])
@login_required
def  add_user():
    
    form=RegisterForm()
    title="Add User"
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user=User(
            name=form.name.data,
            username=form.username.data, password=hashed_password, 
            email=form.email.data, 
            mobile=form.mobile.data, 
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


# edit from model
class EditForm(FlaskForm):
    def __init__(self, current_user, *args, **kwargs):
        super(EditForm, self).__init__(*args, **kwargs)       
        self.current_user = current_user
    
    name = StringField(
        'Name',
        validators=[InputRequired(), Length(min=4, max=30)],
       
    ) 
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=4, max=25)],
        
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
        
    
    role = SelectField(
        'Role',
        choices=[( 'Influencer'), ( 'Sponsor')],
        validators=[InputRequired()],
        
    )    
    
     
    
    submit=SubmitField("Register")  
    
    def validate_username(self, username):
        if username.data != self.current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("Username already exists. Please choose a different one.")

    def validate_email(self, email):
        if email.data != self.current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exists. Please choose a different one.")
    
    
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
    form=EditForm(current_user=current_user)
    
    if form.validate_on_submit():
        user.name=form.name.data
        user.username=form.username.data        
        user.email=form.email.data
        user.mobile=form.mobile.data
        user.role=form.role.data        
          
                    
        db.session.add(user)
        db.session.commit()
        flash(f"{user.name} has been updated","success")
        
        return redirect(url_for('dashboard'))
    
    form.name.data=user.name
    form.username.data=user.username
    form.email.data=user.email
    form.mobile.data=user.mobile
    form.role.data=user.role    
    
    if form.errors:
        for error_msg in form.errors.values():
            flash(error_msg[0], 'danger')
    
    return render_template('edit_user.html',form=form,user=user)





if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
