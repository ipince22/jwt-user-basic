"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, Todo, User
#JWT - SECURITY
#from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)
#login---------------------------------------------------------
@app.route('/login', methods=["POST"])
def login():
    if request.method == "POST":
        username = request.json["username"]
        password = request.json["password"]

        # Validate
        if not username:
            return jsonify({"error": "username Invalid"}), 400
        if not password:
            return jsonify({"error": "Password Invalid"}), 400
        
        user = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({"error": "User not found"}), 400
        
        #if not check_password_hash(user.password, password):
        #    return jsonify({"error": "Wrong password"}), 400
        
        # Create Access Token
        expiration_date = datetime.timedelta(days=1)
        #expiration_date = datetime.timedelta(minutes=1)
        access_token = create_access_token(identity=username, expires_delta=expiration_date)

        request_body = {
            "user": user.serialize(),
            "token": access_token
        }

        return jsonify(request_body), 200

# --User--------------------------------------------------------
@app.route('/user', methods=['GET'])
def listarUsuarios():
    users = User.query.all()
    request = list(map(lambda user:user.serialize(),users))    
    return jsonify(request), 200

@app.route('/user/<int:id>', methods=['GET'])
def lista_usuario(id):
    #user = User.query.get(id)
    user = User.query.filter_by(id=id).first()
    if user is None:
        raise APIException("Message:No se encontro el user",status_code=404)
    request = user.serialize()
    return jsonify(request), 200

@app.route('/user', methods=["POST"])
def crear_usuarios():
    data = request.get_json()
    #hashed_password = generate_password_hash(data["password"],method='sha256')
    user1 = User(username=data["username"],email=data["email"],password=data["password"])
    db.session.add(user1)
    db.session.commit()
    return jsonify("Message : Se adiciono un usuario!"),200

@app.route('/user/<id>', methods=["DELETE"])
@jwt_required()
def delete_usuarios(id):
    current_user = get_jwt_identity()
    user1 = User.query.get(id)
    if user1 is None:
        raise APIException("usuario no existe!",status_code=404)
    db.session.delete(user1)
    db.session.commit()
    return jsonify({"Proceso realizado con exito por el usuario:" : current_user}),200

# --to do list--------------------------------------------------------
@app.route('/todo', methods=['GET'])
def listarTodos():
    todos = Todo.query.all()
    request = list(map(lambda todo:todo.serialize(),todos))    
    return jsonify(request), 200

@app.route('/todo/<int:id>', methods=['GET'])
def listarItem(id):
    #todo1 = Todo.query.get(id)
    todo1 = Todo.query.filter_by(id=id).first()
    if todo1 is None:
        return APIException({"message": "No se encontro el item"},status_code=404)
    request = todo1.serialize()
    return jsonify(request), 200

@app.route('/todo', methods=['POST'])
def crearTodo():
    return jsonify("Metodo Post"), 200

@app.route('/todo', methods=['PUT'])
def updateTodo():
    return jsonify("Metodo PUT"), 200

@app.route('/todo', methods=['DELETE'])
def deleteTodo():
    return jsonify("Metodo DELETE"), 200












# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
