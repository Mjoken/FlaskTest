from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    recipes = db.relationship('Recipe', backref='author', lazy=True)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_user():
    return dict(User=User)


@app.route('/')
def index():
    recipes = Recipe.query.order_by(Recipe.id.desc()).limit(3).all()
    return render_template('index.html', recipes=recipes)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email уже зарегистрирован!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь войдите', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Ошибка при регистрации', 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        flash('Неверный email или пароль', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    user_recipes = Recipe.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', user=current_user, recipes=user_recipes)


@app.route('/create-recipe', methods=['GET', 'POST'])
@login_required
def create_recipe():
    if request.method == 'POST':
        title = request.form['title']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        image = request.files.get('image')
        image_filename = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            image.save(image_path)
            image_filename = unique_name

        new_recipe = Recipe(
            title=title,
            ingredients=ingredients,
            instructions=instructions,
            image=image_filename,
            user_id=current_user.id
        )

        try:
            db.session.add(new_recipe)
            db.session.commit()
            flash('Рецепт успешно создан!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании рецепта: {str(e)}', 'error')

    return render_template('create_recipe.html')


@app.route('/recipes')
def recipes():
    all_recipes = Recipe.query.all()
    return render_template('recipes.html', recipes=all_recipes)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)