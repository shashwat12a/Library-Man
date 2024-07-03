from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_classful import FlaskView
from flask.views import MethodView
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from sqlalchemy import ForeignKey, DateTime
from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Length, NumberRange

app = Flask(__name__)
hello = 123
bootstrap = Bootstrap(app)
app.secret_key = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    author = db.Column(db.String(100), unique=False, nullable=True)
    edition = db.Column(db.String(100), unique=False, nullable=True)
    stock = db.Column(db.String(100), unique=False, nullable=True)

    issues = db.relationship('BookIssue', back_populates='book', cascade='all, delete-orphan')

class Reader(db.Model):
    __tablename__ = 'readers'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), unique=False, nullable=False)
    lname = db.Column(db.String(100), unique=False, nullable=True)
    address = db.Column(db.String(100), unique=False, nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.Integer, nullable=True, unique=True)

    issues = db.relationship('BookIssue', back_populates='reader', cascade='all, delete-orphan')

class BookIssue(db.Model):
    __tablename__ = 'book_issues'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, ForeignKey('books.id'), nullable=False)
    reader_id = db.Column(db.Integer, ForeignKey('readers.id'), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    book = db.relationship('Book', back_populates='issues')
    reader = db.relationship('Reader', back_populates='issues')

# def seedUsers():
#     user = User(username="shashwat", password=generate_password_hash("hello123"))
#     db.session.add(user)
#     db.session.commit()
# def seedBooks():
#     book = Book(name="Catcher In The Rye",author="J.D. Salinger", edition="First Edition", stock=10)
#     db.session.add(book)
#     book2 = Book(name="To Kill a MockingBird",author="Harper Lee", edition="First Edition", stock=100)
#     db.session.add(book2)
#     db.session.commit()

class LoginView(FlaskView):
    methods = ["GET", "POST"]

    def index(self):
        # admin = User(username="admin", password=generate_password_hash("admin123"))
        # db.session.add(admin)
        # db.session.commit()
        return render_template('login.html')
    
    def post(self):
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('DashboardView:index'))
        else:
            flash('Invalid username or password', 'error')
        return render_template('login.html')

class LogoutView(FlaskView):
    decorators = [login_required]
    def index(self):
        logout_user()
        return redirect(url_for('LoginView:index'))

class DashboardView(FlaskView):
    decorators = [login_required]
    def index(self):
        return render_template('dashboard.html')

class BooksView(FlaskView):
    methods = ['GET','POST']
    # decorators = [login_required]
    def index(self):
        books = Book.query.all()
        return render_template('books.html', books=books)
    
    def post(self):
        name = request.form['name']
        author = request.form['author']
        edition = request.form['edition']

        book = Book(name=name,author=author,edition=edition)
        db.session.add(book)
        db.session.commit()
        flash('Book Added', 'success')
        return redirect('BooksView:index')

class ReadersView(FlaskView):
    methods = ['GET', 'POST']
    # decorators = [login_required]
    def index(self):
        readers = Reader.query.all()
        return render_template('readers.html', readers=readers)
        
    def post(self):
        first_name = request.form['first']
        last_name = request.form['last']
        address = request.form['address']
        email = request.form['email']
        phone = request.form['phone']

        reader = Reader(first_name=first_name,last_name=last_name,address=address,email=email,phone=phone)
        db.session.add(reader)
        db.session.commit()
        flash('Reader added!', 'success')
        readers = Reader.query.all()
        return render_template('readers.html', readers=readers)

class UserForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=3,max=15)])
    password = StringField('password', validators=[DataRequired(), Length(min=4,max=100)])
    submit = SubmitField('Submit')

class UsersListView(MethodView):
    decorators = [login_required]
    def get(self):
        users = User.query.all()
        return render_template('users.html', users=users)
    
class UserDetailView(MethodView):
    decorators = [login_required]
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        form = UserForm(obj=user)
        return render_template('user_detail.html', user=user, form=form)

    def post(self, user_id):
        user = User.query.get_or_404(user_id)
        form = UserForm(request.form, obj=user)
        if form.validate():
            form.populate_obj(user)
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('user_list'))
        return render_template('user_detail.html', user=user, form=form)

class UserDeleteView(MethodView):
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('user_list'))

class UserCreateView(MethodView):
    decorators = [login_required]
    def get(self):
        form = UserForm()
        return render_template('user_form.html', form=form)

    def post(self):
        form = UserForm(request.form)
        if form.validate():
            new_user = User(
                username=form.username.data,
                password=generate_password_hash(form.password.data)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('user_list'))
        return render_template('user_form.html', form=form)

class ReaderForm(FlaskForm):
    fname = StringField('First name', validators=[DataRequired(), Length(min=3,max=15)])
    lname = StringField('Last Name', validators=[DataRequired(), Length(min=3,max=15)])
    address = StringField("Address", validators=[DataRequired(),Length(min=6,max=100)])
    phone = StringField('phone', validators=[DataRequired(),Length(min=10,max=15)])
    email = StringField('email', validators=[DataRequired(), Length(min=4,max=100)])
    submit = SubmitField('Submit')

class ReadersListView(MethodView):
    decorators = [login_required]
    def get(self):
        readers = Reader.query.all()
        return render_template('Readers.html', readers=readers)

class ReaderDetailView(MethodView):
    decorators = [login_required]
    def get(self, reader_id):
        reader = Reader.query.get_or_404(reader_id)
        form = ReaderForm(obj=reader)
        return render_template('reader_detail.html', reader=reader, form=form)
    
    def post(self, reader_id):
        reader = Reader.query.get_or_404(reader_id)
        form = ReaderForm(request.form, obj=reader)
        if form.validate():
            form.populate_obj(reader)
            db.session.commit()
            flash('Reader updated successfully!', 'success')
            return redirect(url_for('reader_list'))
        return render_template('reader_detail.html', reader=reader, form=form)

class ReaderCreateView(MethodView):
    decorators = [login_required]
    def get(self):
        form = ReaderForm()
        return render_template('reader_form.html', form=form)

    def post(self):
        form = ReaderForm(request.form)
        if form.validate():
            new_reader = Reader(
                fname=form.fname.data,
                lname=form.lname.data,
                address=form.address.data,
                phone=form.phone.data,
                email=form.email.data,
            )
            db.session.add(new_reader)
            db.session.commit()
            flash('Reader created successfully!', 'success')
            return redirect(url_for('reader_list'))
        return render_template('reader_form.html', form=form)

class ReaderDeleteView(MethodView):
    def get(self, reader_id):
        reader = Reader.query.get_or_404(reader_id)
        db.session.delete(reader)
        db.session.commit()
        flash('Reader deleted successfully!', 'success')
        return redirect(url_for('reader_list'))

class BookForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3,max=100)])
    author = StringField('Author', validators=[DataRequired(), Length(min=3,max=100)])
    edition = StringField('Edition', validators=[DataRequired(), Length(min=1,max=40)])
    stock = IntegerField('Stock Available', validators=[DataRequired()])
    submit = SubmitField('Submit')

class BooksListView(MethodView):
    decorators = [login_required]
    def get(self):
        books = Book.query.all()
        return render_template('books.html', books=books)

class BookDetailView(MethodView):
    decorators = [login_required]
    def get(self, book_id):
        book = Book.query.get_or_404(book_id)
        form = BookForm(obj=book)
        return render_template('book_detail.html', book=book, form=form)
    
    def post(self, book_id):
        book = Book.query.get_or_404(book_id)
        form = BookForm(request.form, obj=book)
        if form.validate():
            form.populate_obj(book)
            db.session.commit()
            flash('Book updated successfully!', 'success')
            return redirect(url_for('book_list'))
        return render_template('book_detail.html', book=book, form=form)

class BookCreateView(MethodView):
    decorators = [login_required]
    def get(self):
        form = BookForm()
        return render_template('book_form.html', form=form)

    def post(self):
        form = BookForm(request.form)
        if form.validate():
            new_book = Book(
                name=form.name.data,
                author=form.author.data,
                edition=form.edition.data,
                stock=form.stock.data,
            )
            db.session.add(new_book)
            db.session.commit()
            flash('Book created successfully!', 'success')
            return redirect(url_for('book_list'))
        return render_template('book_form.html', form=form)

class BookDeleteView(MethodView):
    def get(self, book_id):
        book = Book.query.get_or_404(book_id)
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully!', 'success')
        return redirect(url_for('book_list'))

class BookIssueForm(FlaskForm):
    book = SelectField('Book', validators=[DataRequired()], coerce=int)
    reader = SelectField('Reader', validators=[DataRequired()], coerce=int)
    issue_date = DateTimeField('Issue Date', format='%Y-%m-%d %H:%M:%S')
    return_date = DateTimeField('Return Date', format='%Y-%m-%d %H:%M:%S')
    quantity = IntegerField('Quantity')
    submit = SubmitField('Issue Book')

    def __init__(self, *args, **kwargs):
        super(BookIssueForm, self).__init__(*args, **kwargs)
        self.book.choices = [(book.id, book.name) for book in Book.query.all()]
        self.reader.choices = [(reader.id, reader.fname+" "+reader.lname) for reader in Reader.query.all()]

class BookIssueListView(MethodView):
    decorators = [login_required]
    def get(self):
        book_issues = BookIssue.query.all()
        return render_template('book_issues.html', book_issues=book_issues)

class BookIssueDetailView(MethodView):
    decorators = [login_required]
    def get(self, issue_id):
        issue = BookIssue.query.get_or_404(issue_id)
        form = BookIssueForm(obj=issue)
        return render_template('issue_detail.html', issue=issue, form=form)
    
    def post(self, issue_id):
        issue = BookIssue.query.get_or_404(issue_id)
        form = BookIssueForm(request.form, obj=issue)
        if form.validate():
            form.populate_obj(issue)
            db.session.commit()
            flash('Book updated successfully!', 'success')
            return redirect(url_for('issue_list'))
        return render_template('issue_detail.html', issue=issue, form=form)

class BookIssueCreateView(MethodView):
    decorators = [login_required]
    def get(self):
        form = BookIssueForm()
        return render_template('issue_form.html', form=form)

    def post(self):
        form = BookIssueForm(request.form)
        if form.validate():
            new_issue = BookIssue(
                book_id=form.book.data,
                reader_id=form.reader.data,
                issue_date=datetime.utcnow(),
                quantity=form.quantity.data,
                return_date=None,
            )
            db.session.add(new_issue)
            db.session.commit()
            book = Book.query.get_or_404(form.book.data)
            book.stock = int(book.stock) - int(form.quantity.data)
            db.session.commit()
            flash('Issue created successfully!', 'success')
            return redirect(url_for('issue_list'))
        return render_template('issue_form.html', form=form)

class BookReturnView(MethodView):
    def get(self, issue_id):
        issue = BookIssue.query.get_or_404(issue_id)
        issue.return_date = datetime.utcnow()
        book = Book.query.get_or_404(issue.book.id)
        book.stock = int(book.stock) + int(issue.quantity)
        db.session.commit()
        flash('Book Returned successfully!', 'success')
        return redirect(url_for('issue_list'))

# class UsersView(FlaskView):
#     methods = ['GET', 'POST', 'DELETE']
#     # decorators = [login_required]
#     def index(self):
#         users = User.query.all()
#         return render_template('users.html', users=users)
        
#     def post(self):
#         username = request.form['username']
#         password = request.form['password']
#         password_hash = generate_password_hash(password)
#         user = User(username=username,password=password_hash)
#         db.session.add(user)
#         db.session.commit()
#         flash('User added!', 'success')
#         users = User.query.all()
#         return render_template('users.html', users=users)
    
#     def delete(self):
#         flash("mmmmm", "success")
#         users = User.query.all()
#         return render_template('users.html', users=users)

LoginView.register(app)
LogoutView.register(app)
DashboardView.register(app)
# BooksView.register(app)
# ReadersView.register(app)

app.add_url_rule('/users/', view_func=UsersListView.as_view('user_list'))
app.add_url_rule('/users/create', view_func=UserCreateView.as_view('user_create'))
app.add_url_rule('/users/detail/<int:user_id>/', view_func=UserDetailView.as_view('user_detail'))
app.add_url_rule('/users/<int:user_id>/delete/', view_func=UserDeleteView.as_view('user_delete'))

app.add_url_rule('/readers/', view_func=ReadersListView.as_view('reader_list'))
app.add_url_rule('/readers/create', view_func=ReaderCreateView.as_view('reader_create'))
app.add_url_rule('/readers/detail/<int:reader_id>/', view_func=ReaderDetailView.as_view('reader_detail'))
app.add_url_rule('/readers/<int:reader_id>/delete/', view_func=ReaderDeleteView.as_view('reader_delete'))

app.add_url_rule('/books/', view_func=BooksListView.as_view('book_list'))
app.add_url_rule('/books/create', view_func=BookCreateView.as_view('book_create'))
app.add_url_rule('/books/detail/<int:book_id>/', view_func=BookDetailView.as_view('book_detail'))
app.add_url_rule('/books/<int:book_id>/delete/', view_func=BookDeleteView.as_view('book_delete'))

app.add_url_rule('/issues/', view_func=BookIssueListView.as_view('issue_list'))
app.add_url_rule('/issues/create', view_func=BookIssueCreateView.as_view('issue_create'))
app.add_url_rule('/issues/detail/<int:issue_id>/', view_func=BookIssueDetailView.as_view('issue_detail'))
app.add_url_rule('/issues/<int:issue_id>/return/', view_func=BookReturnView.as_view('issue_return'))


# @app.route("/seed")
# def seed():
#     seedBooks()
#     seedUsers()
#     return "Books Seeded!"

if __name__ == '__main__':
    app.run(debug=True)
