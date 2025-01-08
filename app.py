from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, FlaskForm
from wtforms import TextAreaField
from wtforms.validators import DataRequired


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'FLASK_KEY')

# CKEditor and Bootstrap5
ckeditor = CKEditor(app)
Bootstrap5(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect users to login page if they are not authenticated

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://posts_db_er94_user:3FhSViNG7znjjdYnx4Bf0Ba9UrpZWCde@dpg-ctun64pu0jms73f9d2sg-a.oregon-postgres.render.com/posts_db_er94')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Optional, reduces overhead

# Initialize the database
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)



# CONFIGURE TABLES

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    # Relationship to BlogPost
    posts = db.relationship('BlogPost', backref='creator', lazy=True)

    def set_password(self, password):
        """Hashes the password before storing it in the database."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the entered password matches the hashed one."""
        return check_password_hash(self.password, password)
    
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    post = db.relationship('BlogPost', backref='comments', lazy=True)
    author = db.relationship('User', backref='comments', lazy=True)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    # Foreign key to the User model
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship to the User model (no need for back_populates)
    # The 'backref' 'creator' is automatically created in the 'User' model
    

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])




with app.app_context():
    db.create_all()  # This will create the tables based on the updated models
    
    
gravatar = Gravatar(app,
                   size=100,
                   rating='g',
                   default='retro',
                   force_default=False,
                   force_lower=False,
                   use_ssl=False,
                   base_url=None)


# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Retrieve user by ID

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return redirect(url_for('get_all_posts'))  # Changed from 'index' to 'get_all_posts'
        return f(*args, **kwargs)
    return decorated_function


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if the user already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for("login"))

        # Create a new user entry
        new_user = User(
            username=form.username.data,
            email=form.email.data
            )
        new_user.set_password(form.password.data)  # Hash password before storing
        
        if User.query.count() == 0:  # If there are no users yet, make the first user an admin
            new_user.id = 1
        
        db.session.add(new_user)
        db.session.commit()
        
        
        login_user(new_user)  # Log in the user immediately after registration
        return redirect(url_for('get_all_posts'))  # Redirect to home page
        

    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Check if the user exists
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('get_all_posts'))  # Redirect to home page
        else:
            flash("Login failed. Check your email and/or password and try again.", "danger")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()

    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            creator=current_user,  # Use the backref name 'creator' instead of author_id
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# Update the show_post route to handle comments properly
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login to post comments.", "error")
            return redirect(url_for('login'))
            
        new_comment = Comment(
            text=comment_form.text.data,
            post=requested_post,  # Use the relationship
            author=current_user   # Use the relationship
        )
        
        try:
            db.session.add(new_comment)
            db.session.commit()
            flash("Your comment has been posted!", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error posting comment. Please try again.", "error")
            print(f"Error: {str(e)}")  # For debugging
            
        return redirect(url_for('show_post', post_id=post_id))

    # Get all comments for this post
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.id.desc()).all()
    return render_template("post.html", post=requested_post, comment_form=comment_form, comments=comments)


@app.route("/delete/<int:post_id>")
@admin_only  # Only accessible by the admin
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")





if __name__ == "__main__":
    app.run(debug=True, port=5002)


# Hello
# Hello@hello.com  
# hello123 
# hello123