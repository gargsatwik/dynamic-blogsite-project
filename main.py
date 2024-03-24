import functools
import flask
import flask_ckeditor
import flask_login
import wtforms
import werkzeug
from flask_login import login_required, current_user
from flask import Flask, render_template, redirect, flash, url_for
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from flask_wtf import FlaskForm
from flask_ckeditor import CKEditor
from datetime import date
import smtplib
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
Bootstrap5(app)
CKEditor(app)
year = date.today().year
my_email = os.environ.get('MY_EMAIL')
password = os.environ.get('MY_PASSWORD')
log_in_manager = flask_login.LoginManager()
log_in_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


class NewUser(flask_login.UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=False, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String, nullable=False)

    def is_active(self):
        self.is_active()


class NewPostForm(FlaskForm):
    title = wtforms.StringField("Title", validators=[wtforms.validators.DataRequired()])
    subtitle = wtforms.StringField("Subtitle", validators=[wtforms.validators.DataRequired()])
    author = wtforms.StringField("Author", validators=[wtforms.validators.DataRequired()])
    image_url = wtforms.StringField("Image url", validators=[wtforms.validators.DataRequired(),
                                                             wtforms.validators.URL()])
    body = flask_ckeditor.CKEditorField("Body", validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField("Create Post")


class LoginForm(FlaskForm):
    email = wtforms.EmailField("Email", validators=[wtforms.validators.DataRequired()])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField("Log In")


class RegisterForm(FlaskForm):
    username = wtforms.StringField("Username", validators=[wtforms.validators.DataRequired()])
    email = wtforms.EmailField("Email", validators=[wtforms.validators.DataRequired()])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField("Log In")


with app.app_context():
    db.create_all()


@log_in_manager.user_loader
def load_user(user_id):
    return NewUser.query.get(user_id)


def admin_required(func):
    @functools.wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            flask.abort(403)
        return func(*args, **kwargs)
    return decorated_function


def is_admin(user):
    if user.id == 1:
        return True
    else:
        return False


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if flask.request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated, year=year))
        else:
            return render_template('login.html', form=form, logged_in=current_user.is_authenticated, year=year)
    elif flask.request.method == 'POST':
        email = form.email.data
        user_password = form.password.data
        user = NewUser.query.filter_by(email=email).first()
        if not user:
            flash("User Not Registered!")
            return redirect(url_for('register', logged_in=current_user.is_authenticated, year=year))
        if not werkzeug.security.check_password_hash(user.password, user_password):
            flash("Incorrect Password! Please try again.")
            return redirect(url_for('login', logged_in=current_user.is_authenticated, year=year))
        flask_login.login_user(user)
        return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated, year=year))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if flask.request.method == 'GET':
        return render_template('register.html', form=form, logged_in=current_user.is_authenticated, year=year)
    elif flask.request.method == 'POST':
        username = form.username.data
        email = form.email.data
        client = NewUser.query.filter_by(email=email).first()
        if client:
            flash("Already registered with that email! Login instead!")
            return redirect('/')
        else:
            new_user = NewUser(name=username, email=email,
                               password=werkzeug.security.generate_password_hash(form.password.data,
                                                                                 method="pbkdf2:sha256", salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated, year=year))


@app.route('/all-posts')
@login_required
def get_all_posts():
    posts = []
    blogs = BlogPost.query.all()
    for blog in blogs:
        new_format = {
            "id": blog.id,
            "title": blog.title,
            "date": blog.date,
            "body": blog.body,
            "author": blog.author,
            "image_url": blog.img_url,
            "subtitle": blog.subtitle,
        }
        posts.append(new_format)
    return render_template("index.html", all_posts=posts, year=year, admin=is_admin(current_user),
                           logged_in=current_user.is_authenticated)


@app.route('/show_post/<int:post_id>')
@login_required
def show_post(post_id):
    blogs = BlogPost.query.all()
    requested_post = ""
    for blog in blogs:
        if blog.id == post_id:
            requested_post = {
                "id": blog.id,
                "title": blog.title,
                "date": blog.date,
                "body": blog.body,
                "author": blog.author,
                "image_url": blog.img_url,
                "subtitle": blog.subtitle,
            }
    return render_template("post.html", post=requested_post, year=year, logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def new_post():
    form = NewPostForm()
    if flask.request.method == "GET":
        return render_template("make-post.html", form=form, year=year, header="New Post",
                               logged_in=current_user.is_authenticated)
    elif flask.request.method == "POST":
        title = form.title.data
        subtitle = form.subtitle.data
        author = form.author.data
        image_url = form.image_url.data
        body = form.body.data
        post_date = date.today().strftime("%B %d %Y")
        new_blog = BlogPost(title=title, subtitle=subtitle, author=author, img_url=image_url, body=body, date=post_date,
                            year=year)
        db.session.add(new_blog)
        db.session.commit()
        return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated, year=year))


@app.route("/edit-post/<post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    blog = BlogPost.query.get(post_id)
    edit_form = NewPostForm(
        title=blog.title,
        subtitle=blog.subtitle,
        image_url=blog.img_url,
        author=blog.author,
        body=blog.body
    )
    if flask.request.method == "GET":
        return render_template("make-post.html", year=year, header="Edit Post", form=edit_form,
                               logged_in=current_user.is_authenticated)
    elif flask.request.method == "POST":
        blog.subtitle = edit_form.subtitle.data
        blog.author = edit_form.author.data
        blog.image_url = edit_form.image_url.data
        blog.body = edit_form.body.data
        blog.post_date = date.today().strftime("%B %d %Y")
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id, logged_in=current_user.is_authenticated, year=year))


@app.route("/delete/<post_id>", methods=["GET"])
@admin_required
def delete_post(post_id):
    blog = BlogPost.query.get(post_id)
    db.session.delete(blog)
    db.session.commit()
    return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated, year=year))


@app.route('/logout')
@login_required
def log_out():
    flask_login.logout_user()
    return redirect(url_for('login', logged_in=current_user.is_authenticated, year=year))


@app.route("/about")
def about():
    return render_template("about.html", year=year, logged_in=current_user.is_authenticated)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if flask.request.method == "GET":
        return render_template("contact.html", year=year, logged_in=current_user.is_authenticated)
    elif flask.request.method == "POST":
        name = flask.request.form['name']
        email = flask.request.form['email']
        phone_number = flask.request.form['phone']
        message = flask.request.form['message']
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=my_email, password=password)
            connection.sendmail(from_addr=my_email,
                                to_addrs=os.environ.get("RECEIVER_EMAIL"),
                                msg=f"Subject: New User\n\n"
                                    f"Name: {name}\n"
                                    f"Email: {email}\n"
                                    f"Phone Number: {phone_number}\n"
                                    f"Message: {message}"
                                )
        return redirect(url_for("contact", logged_in=current_user.is_authenticated, year=year))


if __name__ == "__main__":
    app.run(debug=False, port=5003)
