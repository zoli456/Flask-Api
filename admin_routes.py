from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from models import User, Role, UserRole, db, bcrypt, Message
from models import update_user_schema
from auth_utils import roles_required

admin_bp = Blueprint('admin', __name__)  # Create an admin blueprint

@admin_bp.route('/delete-user/<int:user_id>', methods=['DELETE'])
@jwt_required()
@roles_required('ADMIN')
def admin_delete_user(user_id):
    """Allow Admins to delete user accounts."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200

@admin_bp.route('/update-user/<int:user_id>', methods=['PUT'])
@jwt_required()
@roles_required('ADMIN')
def admin_update_user(user_id):
    """Allow Admins to update a user's email or password."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    errors = update_user_schema.validate(data)
    if errors:
        return jsonify(errors), 400

    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

@admin_bp.route('/add-role', methods=['POST'])
@jwt_required()
@roles_required('ADMIN')
def admin_add_role():
    """Allow Admins to assign a role to a user."""
    data = request.get_json()
    user_id = data.get('user_id')
    role_name = data.get('role')

    if not user_id or not role_name:
        return jsonify({'message': 'User ID and role are required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({'message': 'Role not found'}), 404

    if UserRole.query.filter_by(user_id=user.id, role_id=role.id).first():
        return jsonify({'message': 'User already has this role'}), 400

    new_user_role = UserRole(user_id=user.id, role_id=role.id)
    db.session.add(new_user_role)
    db.session.commit()

    return jsonify({'message': f'Role {role_name} added to user {user.username}'}), 200


@admin_bp.route('/remove-role', methods=['POST'])
@jwt_required()
@roles_required('ADMIN')
def admin_remove_role():
    """Allow Admins to remove a role from a user."""
    data = request.get_json()
    user_id = data.get('user_id')
    role_name = data.get('role')

    if not user_id or not role_name:
        return jsonify({'message': 'User ID and role are required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({'message': 'Role not found'}), 404

    user_role = UserRole.query.filter_by(user_id=user.id, role_id=role.id).first()
    if not user_role:
        return jsonify({'message': 'User does not have this role'}), 400

    db.session.delete(user_role)
    db.session.commit()

    return jsonify({'message': f'Role {role_name} removed from user {user.username}'}), 200

@admin_bp.route('/admin/delete-message/<int:message_id>', methods=['DELETE'])
@jwt_required()
@roles_required('ADMIN')
def admin_delete_message(message_id):
    """Allow Admins to delete any message."""
    message = Message.query.get(message_id)

    if not message:
        return jsonify({'message': 'Message not found'}), 404

    db.session.delete(message)
    db.session.commit()

    return jsonify({'message': 'Message deleted successfully by admin'}), 200