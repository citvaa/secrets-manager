def handler(event=None):
    # Allocate memory until killed by RLIMIT_AS
    chunks = []
    while True:
        chunks.append(b"A" * (10 * 1024 * 1024))
