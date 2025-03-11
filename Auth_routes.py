from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
import datetime
from models import User, Role, UserRole, user_schema
from auth_utils import roles_required

user_bp = Blueprint('user', __name__)

"""def verify_email(email):
    response = requests.get(f'https://api.eva.pingutil.com/email?email={email}')
    data = response.json()
    return data.get('status') == 'valid'"""

def verify_email(email):
    try:
        email = validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError as e:
        return False

def auth_routes(app, db, bcrypt):
    @user_bp.route('/register', methods=['POST'])
    def register():
        # Get the JSON data from the request
        data = request.get_json()

        if not data:
            return jsonify({'message': 'Missing request body'}), 400

        errors = user_schema.validate(data)
        if errors:
            return jsonify({'errors': errors}), 400

        if not verify_email(data.get('email', '')):
            return jsonify({'message': 'Invalid email address'}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        # Create the new user
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()  # Commit to generate user ID

        # Assign the "USER" role
        user_role = Role.query.filter_by(name="USER").first()
        if not user_role:
            user_role = Role(name="USER")
            db.session.add(user_role)
            db.session.commit()  # Commit the new role if it doesn't exist

        # Link the user to the role
        user_role_link = UserRole(user_id=new_user.id, role_id=user_role.id)
        db.session.add(user_role_link)
        db.session.commit()

        return jsonify({'message': 'User registered successfully with USER role'}), 201

    @user_bp.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        # Validate request data
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Email and password are required'}), 400

        user = User.query.filter_by(email=data['email']).first()

        if user and bcrypt.check_password_hash(user.password, data['password']):
            roles = [role.name for role in Role.query.join(UserRole, Role.id == UserRole.role_id)
            .filter(UserRole.user_id == user.id).all()]
            expires = datetime.timedelta(hours=1)
            access_token = create_access_token(identity=str(user.id), additional_claims={
                'username': user.username,
                'email': user.email,
                'roles': roles
            }, expires_delta=expires)
            return jsonify({'access_token': access_token}), 200

        return jsonify({'message': 'Invalid email or password'}), 401

    @user_bp.route('/me', methods=['GET'])
    @jwt_required()
    @roles_required('USER')
    def me():
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({'message': 'User not found'}), 404

        roles = [role.name for role in Role.query.join(UserRole, Role.id == UserRole.role_id)
            .filter(UserRole.user_id == user.id).all()]

        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'roles': roles,
            'created_at': user.created_at,
            'updated_at': user.updated_at
        }), 200

    @user_bp.route('/change-password', methods=['PUT'])
    @jwt_required()
    @roles_required('USER')
    def change_password():
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({'message': 'User not found'}), 404

        data = request.get_json()
        if 'old_password' not in data or 'new_password' not in data:
            return jsonify({'message': 'Old and new password are required'}), 400

        if not bcrypt.check_password_hash(user.password, data['old_password']):
            return jsonify({'message': 'Old password is incorrect'}), 401

        hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        return jsonify({'message': 'Password changed successfully'}), 200

    @user_bp.route('/change-email', methods=['PUT'])
    @jwt_required()
    @roles_required('USER')
    def change_email():
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({'message': 'User not found'}), 404

        data = request.get_json()
        if 'new_email' not in data:
            return jsonify({'message': 'New email is required'}), 400

        if not verify_email(data['new_email']):
            return jsonify({'message': 'Invalid email address'}), 400

        if User.query.filter_by(email=data['new_email']).first():
            return jsonify({'message': 'Email already in use'}), 409

        user.email = data['new_email']
        db.session.commit()

        return jsonify({'message': 'Email changed successfully'}), 200