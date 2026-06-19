def handler(event=None):
    event = event or {}
    return {"message": f"Zdravo, {event.get('name', 'svete')}!"}
