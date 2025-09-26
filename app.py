from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)
#view login

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout' , methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Usuário já existe"}), 400
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuário criado com sucesso"}), 201
    return jsonify({"message": "Dados inválidos"}), 401

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"username": user.username})
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<username>', methods=['PUT'])
@login_required
def update_user_password(username):
    data = request.get_json()
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = data.get('password')
        db.session.commit()
        return jsonify({ "message": f"Usuário {username} atualizado com sucesso"})
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    user = User.query.filter_by(username=username).first()

    if username == current_user.username:
        return jsonify({"message": "Deleção não permitida"}), 403
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({ "message": f"Usuário {username} removido com sucesso"})
    return jsonify({"message": "Usuário não encontrado"}), 404


if __name__ == '__main__':
    app.run(debug=True)