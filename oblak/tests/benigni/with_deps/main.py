import humanize


def handler(event=None):
    n = (event or {}).get("n", 1_000_000)
    return {"formatted": humanize.intcomma(n)}
