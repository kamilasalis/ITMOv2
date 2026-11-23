def get_user(users, user_id):
    """Return the record with the matching user ID."""
    for user in users:
        if "id" in user and user["id"] == user_id:
            return user
    return None
