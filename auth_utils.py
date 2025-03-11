from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from models import Role, UserRole

def roles_required(*required_roles):
    """Decorator to check if a user has the required role(s)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user_roles = [role.name for role in Role.query.join(UserRole, Role.id == UserRole.role_id)
            .filter(UserRole.user_id == current_user_id).all()]

            # Check if user has at least one required role
            if not any(role in user_roles for role in required_roles):
                return jsonify({'message': 'Unauthorized'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
