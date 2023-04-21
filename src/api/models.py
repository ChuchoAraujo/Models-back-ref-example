from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role.serialize()
        }

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)

    def __repr__(self):
        return f'<{self.name}>'

    def __init__(self, name):
        self.name = name

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref=db.backref('members', lazy=True))

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role.serialize()
        }