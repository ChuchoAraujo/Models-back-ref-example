"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Role, Member
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash

# Resto del código


api = Blueprint('api', __name__)


@api.route('/users')
def get_users():
    users = User.query.all()
    serialized_users = [user.serialize() for user in users]
    return jsonify(serialized_users)

@api.route('/login', methods=['POST'])
def create_user():
    # Obtener los datos del usuario desde el cliente
    username = request.json.get('username')
    password = request.json.get('password')
    role_name = request.json.get('role')

    # Verificar si el usuario ya existe
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'El usuario ya existe'}), 400

    # Crear un nuevo usuario

    # Encriptar contraseña
    hashed_password = generate_password_hash(password, method='sha256')

    # Obtener el objeto Role correspondiente al nombre recibido
    role = Role.query.filter_by(name=role_name).first() # Compara la variable de la tabla user con la del cliente
    if not role:
        return jsonify({'message': 'Rol no encontrado'}), 400

    # Crear el nuevo usuario con la relación al rol
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    # Generar un token JWT y devolverlo como respuesta
    access_token = create_access_token(identity=username)
    return jsonify({'user': new_user.serialize(), 'access_token': access_token}), 200