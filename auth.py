from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

# cors = CORS(
#     app,
#     resources={
#         r"/*": {
#             "origins": "http://localhost*",
#             "ports": "8080",
#         }
#     },
# )
app.config["CORS_HEADERS"] = "Content-Type"
app.config['SECRET_KEY'] = 'YYPACIvGjgHNAkLMrizwjsKVwpDLdlIl'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql://root:YYPACIvGjgHNAkLMrizwjsKVwpDLdlIl@monorail.proxy.rlwy.net:12857/railway')
# app.config['SQLALCHEMY_DATABASE_URI'] = (
#     'mysql+mysqlconnector://root:YYPACIvGjgHNAkLMrizwjsKVwpDLdlIl@monorail.proxy.rlwy.net:12857/railway')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(440))
    photo = db.Column(db.String(200))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['POST'])
def register():
    data = request.form
    # data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    name = data.get('name')
    photo = data.get('photo')

    if not all([username, password, email, name, photo]):
        return jsonify({'message': 'All fields are required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400

    user = User(username=username, email=email, name=name, photo=photo)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    # data = request.json
    # email = request.json['email']
    # password = request.json['password']
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password'}), 400

    login_user(user)
    print(current_user, current_user.is_authenticated, user)
    return jsonify({"user": {'username': user.username}, 'url': '/dashboard'}), 200


@app.route('/user/<username>', methods=['GET'])
@login_required
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    return jsonify({'username': user.username, 'email': user.email, 'name': user.name, 'photo': user.photo}), 200


@app.route('/users', methods=['GET'])
@login_required
def get_users():
    users = User.query.all()
    user_list = [{'username': user.username, 'email': user.email, 'name': user.name, 'photo': user.photo} for user in
                 users]
    return jsonify(user_list), 200


@app.route('/check-auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({'authenticated': True}), 200
    else:
        return jsonify({'authenticated': False}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200


with app.app_context():
    db.create_all()


@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': 'Welcome to the protected page!'})


if __name__ == '__main__':
    app.run(debug=True)
