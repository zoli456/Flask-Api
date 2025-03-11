from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Message
from datetime import datetime

messages_bp = Blueprint('messages', __name__)

def validate_message(content):
    if not content or len(content.strip()) < 4 or len(content.strip()) > 1024:
        return False
    return True
@messages_bp.route('/post-message', methods=['POST'])
@jwt_required()
def post_message():
    """Allow authenticated users to post a message."""
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content', '').strip()

    if not validate_message(content):
        return jsonify({'message': 'Message must be between 4 and 1024 characters'}), 400

    new_message = Message(user_id=user_id, content=content)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message posted successfully', 'message_id': new_message.id}), 201

@messages_bp.route('/edit-message/<int:message_id>', methods=['PUT'])
@jwt_required()
def edit_message(message_id):
    """Allow users to edit their own messages."""
    user_id = get_jwt_identity()
    message = Message.query.get(message_id)

    if not message:
        return jsonify({'message': 'Message not found'}), 404
    if message.user_id != user_id:
        return jsonify({'message': 'You can only edit your own messages'}), 403

    data = request.get_json()
    new_content = data.get('content', '').strip()

    if not validate_message(new_content):
        return jsonify({'message': 'Message must be between 4 and 1024 characters'}), 400

    message.content = new_content
    message.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({'message': 'Message updated successfully'}), 200

@messages_bp.route('/delete-message/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    """Allow users to delete their own messages."""
    user_id = get_jwt_identity()
    message = Message.query.get(message_id)

    if not message:
        return jsonify({'message': 'Message not found'}), 404
    if message.user_id != user_id:
        return jsonify({'message': 'You can only delete your own messages'}), 403

    db.session.delete(message)
    db.session.commit()

    return jsonify({'message': 'Message deleted successfully'}), 200

@messages_bp.route('/all-messages', methods=['GET'])
@jwt_required()
def get_all_messages():
    """Return all messages."""
    messages = Message.query.all()
    messages_list = [
        {
            'id': msg.id,
            'user_id': msg.user_id,
            'content': msg.content,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': msg.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for msg in messages
    ]

    return jsonify({'messages': messages_list}), 200