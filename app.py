from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()

db.init_app(app) #passando app para o db
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        #login
        user = User.query.filter_by(username=username).first() #busca no banco e seleciona o primeiro que bate com o username
        
        if (user) and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            print(login_user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"}), 200

        
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route("/logout", methods=['GET'])
@login_required #Evita que usuarios não logados possam deslogar
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"}), 200

@app.route("/register", methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso!"}), 200
    
    return jsonify({"message": "Dados inválidas"}), 400

@app.route("/user/<int:id_user>", methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"Usuario": user.username}
    
    return jsonify({"message": "Usuário não encontrado"}), 404   
    
    
    
@app.route("/user/<int:id_user>", methods=['PUT'])
@login_required
def update_user(id_user):#123
    data = request.json
    user = User.query.get(id_user)
     ##123 != 123 and "user" == "user"
    if id_user != current_user.id and current_user.role == "user": #Somente admnistradores podem editar outros usuarios
        return jsonify({"message": "Operação não permitida"}), 403
    
    
    if user and data.get("password"): #obrigatorio existir um usuario e enviar a senha nova no corpo
        user.password = data.get("password") #envia a senha no body para o user
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso"})
    
    return jsonify({"message": "Usuario não encontrado"}), 404  


@app.route("/user/<int:id_user>", methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)
    
    if current_user.role != 'admin': #Apenas administradores podem fazer deleções
        return jsonify({"message": "Operação não permitida"}), 403
    
    if id_user == current_user.id:   #não deve ser permitido deletar o usuario logado
      return jsonify({"message": "Deleção não permitida"}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} deletado com sucesso!"})
    
@app.route("/hello-world", methods=['GET'])
def hello_world():
    return 'hello_world'


if __name__ == '__main__':
    app.run(debug=True)

