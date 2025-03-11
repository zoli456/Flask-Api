from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from marshmallow import Schema, fields, validate

db = SQLAlchemy()
bcrypt = Bcrypt()

class UserSchema(Schema):
    username = fields.String(required=True, validate=validate.Length(min=5, max=80))
    email = fields.Email(required=True, validate=validate.Length(min=5, max=120))
    password = fields.String(required=True, validate=validate.Length(min=8, max=255))

class UpdateUserSchema(Schema):
    email = fields.Email(validate=validate.Length(min=5, max=120))
    password = fields.String(validate=validate.Length(min=8, max=255))

user_schema = UserSchema()
update_user_schema = UpdateUserSchema()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('messages', lazy=True))