def handler(event=None):
    event = event or {}
    a = int(event.get("a", 6))
    b = int(event.get("b", 7))
    return {"sum": a + b, "product": a * b}
