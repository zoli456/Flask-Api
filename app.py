from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from models import db, Role
from Auth_routes import auth_routes
from Auth_routes import user_bp
from admin_routes import admin_bp
from messages_routes import messages_bp  # Import the messages Blueprint

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_api'
app.config['JWT_SECRET_KEY'] = 'xE96oz5ElIqHhIFvI94ypSGMVOcBfFceNu2qfKtMLHoAjsmd8Hs9rhlvh5EqAWEs'

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Register routes from Auth_routes.py
auth_routes(app, db, bcrypt)

def setup_database(app):
    with app.app_context():
        db.create_all()
        if not Role.query.first():  # Seed default roles if they don't exist
            db.session.add(Role(name='USER'))
            db.session.add(Role(name='ADMIN'))
            db.session.commit()

# Register Blueprints
app.register_blueprint(user_bp, url_prefix='/user')  # User-related endpoints
app.register_blueprint(admin_bp, url_prefix='/admin')  # Admin-only endpoints
app.register_blueprint(messages_bp, url_prefix='/messages')  # Message-related endpoints

if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True)
