def get_user(users, user_id):
    """Return the record with the matching user ID."""
    for user in users:
        if "id" in user and (user["id"] == user_id or ((type(user["id"]) is int and isinstance(user_id, str) and str(user["id"]) == user_id) or (isinstance(user["id"], str) and type(user_id) is int and user["id"] == str(user_id)))):
            return user
    return None
