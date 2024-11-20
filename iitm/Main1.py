from io import BytesIO
from flask import Flask, abort, current_app, request, send_file, url_for, render_template,redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user,login_user,LoginManager,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import FileField, IntegerField, StringField,PasswordField,SubmitField,EmailField,SelectField, TextAreaField
from wtforms.validators import InputRequired,Length,ValidationError,Email,EqualTo,Regexp,NumberRange
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
    email = db.Column(db.String(20), nullable=False, unique=True)
    address = db.Column(db.Text, nullable=False)
    country=db.Column(db.String(20), nullable=False)
    state=db.Column(db.String(20), nullable=False)
    city=db.Column(db.String(20), nullable=False)
    pincode=db.Column(db.Integer, nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(15), nullable=False,default='Active')    
    date_added = db.Column(db.DateTime, default=func.now())
    
    # Backref for flagged users
    flagged_users = db.relationship('FlaggedUsers', backref='user', lazy=True)
    # Backref for professionals
    professionals = db.relationship('Professional', backref='user', lazy=True)
    # Backref for reviews
    reviews = db.relationship('Reviews', backref='user', lazy=True)
    # backref for service requests
    service_requests = db.relationship('ServiceRequests', backref='user', lazy=True)

    def __repr__(self):
        return '<Name %r>' % self.name

class FlaggedUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)    
    date_added = db.Column(db.DateTime, nullable=False, default=func.now())

class Services(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)    
    base_price = db.Column(db.Integer, nullable=False)    
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    
    # Backref for service requests
    service_requests = db.relationship('ServiceRequests', backref='service', lazy=True)
    
    
    

class ServiceRequests(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('reviews.id'))
    description = db.Column(db.Text, nullable=False)    
    status = db.Column(db.String(15), nullable=False,default='Pending')    
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    closing_date = db.Column(db.DateTime)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())

class Professional(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    service=db.Column(db.String(80), nullable=False)
    status = db.Column(db.Boolean, default=False)
    experience = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)
    average_rating = db.Column(db.Float, default=0.0)
    date_requested = db.Column(db.DateTime, nullable=False, default=func.now())
    
    # Backref for reviews
    reviews = db.relationship('Reviews', backref='professional', lazy=True)
    
    # backref for service requests
    service_requests = db.relationship('ServiceRequests', backref='professional', lazy=True)
    
    

class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=False)
    rating = db.Column(db.Integer(), nullable=False)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_requests.id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=func.now())
    
    def update_average_review(self):
        ratings = Reviews.query.filter_by(professional_id=self.professional_id).all()
        if ratings:
            average = sum(r.rating for r in ratings) / len(ratings)
            professional = Professional.query.get(self.professional_id)
            professional.average_rating = average
            db.session.commit()

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
    country = StringField(
        'Country',
        validators=[InputRequired()],
        
    )     
    state = StringField(
        'State',
        validators=[InputRequired()],
        
    )
    city = StringField(
        'City',
        validators=[InputRequired()],
        
    )
    pincode = IntegerField(
        'Pincode',
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
    country = StringField(
        'Country',
        validators=[InputRequired()],
        
    )     
    state = StringField(
        'State',
        validators=[InputRequired()],
        
    )
    city = StringField(
        'City',
        validators=[InputRequired()],
        
    )
    pincode = IntegerField(
        'Pincode',
        validators=[InputRequired()],
        
    )
    
    
    submit=SubmitField("Register")  
    
   
    def validate_email(self, email):
        if email.data != self.current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exists. Please choose a different one.")
            
  
          
# from to accept professional details
class ProfessionalForm(FlaskForm):
    service = SelectField( 'Service',
        choices=[],
        validators=[InputRequired()],
       
    ) 
    
    experience = IntegerField( 'Experiance',
        validators=[InputRequired()],
        
    )
    file = FileField('File', 
            validators=[InputRequired()]
    )
    
    submit=SubmitField("Submit")
    
# form for search
class SearchForm(FlaskForm):
    searched=StringField("Searched",validators=[InputRequired()])
    search_type=StringField("Search Type",validators=[InputRequired()])
    
    
    
    submit=SubmitField("search")
    
class ServiceRequestForm(FlaskForm):
    description = TextAreaField(
        'Description',
        validators=[InputRequired()],
        
    )
    submit=SubmitField("Request") 
    
class FlagForm(FlaskForm):
    description = TextAreaField(
        'Description',
        validators=[InputRequired()],
        
    )
    submit=SubmitField("Submit")

class ReviewForm(FlaskForm):
    title = StringField(
        'Title',
        validators=[InputRequired()],
        
    )
    description = TextAreaField(
        'Description',
        validators=[InputRequired()],
        
    )
    rating = IntegerField(
        'Rating',
        validators=[InputRequired(),
                    NumberRange(min=1, max=10)],
        
    )
    submit=SubmitField("Submit")
    

# to display the request form
@app.route('/review/<int:id>',methods=['GET','POST'])
def review(id):    
    form=ReviewForm()
    if form.validate_on_submit():
        service=ServiceRequests.query.get_or_404(id)
        customer_id=service.customer_id
        professional_id=service.professional_id
        review=Reviews(
            title=form.title.data,
            description=form.description.data,
            rating=form.rating.data,
            user_id=customer_id,
            service_request_id=id,
            professional_id=professional_id,
            )
        db.session.add(review)
        review.update_average_review()
        db.session.commit()
        flash("Review has been submitted","success")
        return redirect(url_for('dashboard'))
    return render_template('review.html',form=form)
    


# book requests
@app.route('/servicerequest/<int:id>/<int:service_id>',methods=['GET','POST'])
def servicerequest(id,service_id):
    form=ServiceRequestForm()
    if form.validate_on_submit():
        service_request=ServiceRequests(
            description=form.description.data,
            professional_id=id,
            customer_id=current_user.id,
            status="Pending",
            service_id=service_id            
            )
        db.session.add(service_request)
        db.session.commit()
        flash("Request has been sent","success")
        return redirect(url_for('service',id=service_id))
    return render_template('servicerequest.html',form=form)

# to show service requests
@app.route('/show_requests',methods=['GET','POST'])
def show_requests():
    if current_user.role=='Customer':
        return redirect(url_for('dashboard'))
    professional=Professional.query.filter_by(user_id=current_user.id).first()
    requests=ServiceRequests.query.filter_by(professional_id=professional.id).all()
    
    
    return render_template('show_servicerequests.html',requests=requests)

# show request on customwer side
@app.route('/show_request_user/<int:id>',methods=['GET','POST'])
def show_request_user(id):
    requests=ServiceRequests.query.filter_by(customer_id=id).all()
    return render_template('show_request_user.html',requests=requests)

# to edit service requests
@app.route('/edit_request/<int:id>',methods=['GET','POST'])
def edit_request(id):
    request=ServiceRequests.query.get_or_404(id)
    form=ServiceRequestForm()
    if form.validate_on_submit():
        request.description=form.description.data
        db.session.commit()
        flash("Request has been updated","success")
        return redirect(url_for('dashboard'))
    form.description.data=request.description
    return render_template('servicerequest.html',form=form)

# to view reviews
@app.route('/professional_dashboard/<int:id>',methods=['GET','POST'])
def professional_dashboard(id):
    professional=Professional.query.filter_by(id=id).first()
    reviews=Reviews.query.filter_by(service_id=id).all()
    return render_template('profess.html',reviews=reviews,professional=professional)

# to accept service requests
@app.route('/accept_request/<int:id>',methods=['GET','POST'])
def accept_request(id):
    request=ServiceRequests.query.filter_by(id=id).first()
    request.status="Accepted"
    db.session.commit()
    flash("Request has been accepted","success")
    return redirect(url_for('show_requests'))

# to reject service requests
@app.route('/reject_request/<int:id>',methods=['GET','POST'])
def reject_request(id):
    request=ServiceRequests.query.filter_by(id=id).first()
    request.status="Rejected"
    db.session.commit()
    flash("Request has been rejected","success")
    return redirect(url_for('show_requests'))

# request page
@app.route('/view_request/<int:id>',methods=['GET','POST'])
def view_request(id):
    request=ServiceRequests.query.filter_by(id=id).first()
    return render_template('view_request.html',request=request)

# to close the request
@app.route('/close_request/<int:id>',methods=['GET','POST'])
def close_request(id):
    request=ServiceRequests.query.filter_by(id=id).first()
    request.status="Closed"
    db.session.commit()
    flash("Request has been closed","success")
    if request.customer_id==current_user.id:
        return redirect(url_for('review',id=id))
    return redirect(url_for('show_requests'))
    
# to flag users
@app.route('/flag_user/<int:id>',methods=['GET','POST'])
def flag_user(id):
    form=FlagForm()
    if form.validate_on_submit():
        flag=FlaggedUsers(
            description=form.description.data,
            user_id=id
            )
        db.session.add(flag)
        db.session.commit()
        flash("User has been flagged","success")
        return redirect(url_for('dashboard'))
    
    return render_template('servicerequest.html',form=form)
    
# to view flagged users
@app.route('/view_flagged_users',methods=['GET','POST'])
def view_flagged_users():
    flagged_users=FlaggedUsers.query.all()
    return render_template('view_flagged_users.html',flagged_users=flagged_users)

# disable a flagged user
@app.route('/disable_user/<int:id>',methods=['GET','POST'])
def disable_user(id):
    flaggeduser=FlaggedUsers.query.filter_by(id=id).first()
    flaggeduser.user.status='Disabled'
    
    db.session.commit()
    flash("User has been disabled","success")
    return redirect(url_for('view_flagged_users'))

# to enable user and delete from flagged users
@app.route('/enable_user/<int:id>',methods=['GET','POST'])
def enable_user(id):
    flaggeduser=FlaggedUsers.query.filter_by(id=id).first()
    flaggeduser.user.status='Active'
    db.session.delete(flaggeduser)
    db.session.commit()
    flash("User has been enabled","success")
    return redirect(url_for('view_flagged_users'))

# pass to navbar
@app.context_processor
def base():
    form=SearchForm()
    return dict(form=form)  #dictonary
    
    
# search function
@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    results = []  # Initialize an empty list for results
    search_type = None

    if form.validate_on_submit():
        search_type = form.search_type.data
        search_query = form.searched.data

        if search_type == 'service':
            # Assuming you have a Service model
            results = Services.query.filter(Services.title.contains(search_query)).all()
        
        elif search_type == 'professional':
            # Search professionals based on user name
            results = Professional.query.filter(Professional.user.has(User.name.contains(search_query))).all()
            
        elif search_type == 'Customer':
            # Search customers based on user name
            results = User.query.filter(User.name.contains(search_query)).all()

        if not results:
            flash('No results found for the given query.', 'warning')

    return render_template('search.html', results=results, search_type=search_type)



    
 
@app.route('/professional',methods=['GET','POST'])
@login_required
def professional():
    if current_user.role != 'Professional':
        abort(403)
        
    form=ProfessionalForm()
    form.service.choices = [(service.id, service.title) for service in Services.query.all()]
    
    if form.validate_on_submit():
        
        file = form.file.data
        filename = file.filename
        content = file.read()
        
        service_id = form.service.data
        service = Services.query.get(service_id)
        prof=Professional(
            user_id=current_user.id,
            service=service.title,
            service_id=service_id,
            experience=form.experience.data,
            filename=filename,
            content=content
        )
        
        db.session.add(prof)
        db.session.commit()
        flash("Professional details sent successfully", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('professional.html',form=form)
 
# to display all request professionals
@app.route('/request_authorization')
def request_authorization():
    professionals = Professional.query.filter_by(status=False).all()
    return render_template('request_authorization.html', professionals=professionals)


# authorize professionals
@app.route('/authorize_professional/<int:id>',methods=['POST','GET'])
def authorize_professional(id):
    professional = Professional.query.get(id)
    professional.status = True
    db.session.add(professional)
    db.session.commit()
    flash(f"{professional.user.name} authorized successfully", "success")
    return redirect(url_for('request_authorization'))

@app.route('/authorize_professional/download/<int:id>')
def download(id):
    professional = Professional.query.get_or_404(id)
    return send_file(BytesIO(professional.content),as_attachment=True,download_name=professional.filename)
 

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
            state=form.address.data,
            city=form.city.data,
            country=form.country.data,
            pincode=form.pincode.data,            
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
@app.route('/')
@app.route('/services')
def show_services():
    services=Services.query.order_by(Services.date_posted.desc()).all()
    
    return render_template('show_services.html',services=services)
    
# individual service pages
@app.route('/service/<int:id>') 
def service(id):
    service=Services.query.get_or_404(id)
    professionals = Professional.query.filter(
    Professional.service_id == id,
    Professional.status == True
    ).order_by(Professional.average_rating.desc()).all()
    
    
    return render_template('service.html',service=service,professionals=professionals)

# edit service
@app.route('/service/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_service(id):
    
    if current_user.role != 'Admin':
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
@app.route('/service/delete/<int:id>', methods=['POST', 'GET'])
@login_required
def delete_service(id):
    if current_user.role != 'Admin':
        abort(403)

    service = Services.query.get_or_404(id)
    
    for service_request in service.service_requests:
        for review in service_request.reviews:
            db.session.delete(review)
        db.session.delete(service_request)


    # Reset status of associated professionals
    for professional in Professional.query.filter_by(service_id=id).all():
        professional.status = False

    # Delete the service
    db.session.delete(service)
    db.session.commit()

    flash(f"{service.title} has been deleted", "danger")
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





@app.route('/about/<username>')
def about_page(username):
    return f'<h1>This is an about page of {username}</h1>'

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    requests=ServiceRequests.query.filter_by(customer_id=current_user.id).all()
    if current_user.role=='Professional':
        professional=Professional.query.filter_by(user_id=current_user.id).first()
        return render_template('dashboard.html',professional=professional,user=current_user,requests=requests)
    
    # to show service requests and history
    requests=ServiceRequests.query.filter_by(customer_id=current_user.id).all()
    
    
    return render_template('dashboard.html',user=current_user,requests=requests)

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
@app.route('/user/delete/<int:id>', methods=['POST', 'GET'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            # Begin a database transaction
            with db.session.begin():
                # Delete associated service requests for this user
                service_requests = ServiceRequests.query.filter_by(customer_id=user.id).all()
                for service_request in service_requests:
                    db.session.delete(service_request)

                # Delete associated professionals and their reviews
                for professional in user.professionals:
                    for review in professional.reviews:
                        db.session.delete(review)
                    db.session.delete(professional)

                # Delete flagged users
                for flagged_user in user.flagged_users:
                    db.session.delete(flagged_user)

                # Delete reviews made by the user
                for review in user.reviews:
                    db.session.delete(review)

                # Now delete the user itself
                db.session.delete(user)
            
            # Commit the transaction
            db.session.commit()

            flash(f"{user.name} has been deleted successfully", "danger")
            return redirect(url_for('login'))  # Redirect to login page after deletion

        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            flash(f"Error occurred: {str(e)}", "danger")
            return redirect(url_for('users'))  # Redirect back to user listing page

    return render_template('users.html', user=user)


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
        user.state=form.address.data
        user.city=form.city.data
        user.country=form.country.data
        user.pincode=form.pincode.data         
          
                    
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
