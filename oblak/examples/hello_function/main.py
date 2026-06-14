"""A minimal benign example function for the Oblak platform.

The execution contract (how `handler` is invoked inside the MicroVM) is finalized by
Member 3; this serves as a benign test case for the upload pipeline.
"""


def handler(event: dict | None = None) -> dict:
    event = event or {}
    name = event.get("name", "svete")
    return {"message": f"Zdravo, {name}!"}


if __name__ == "__main__":
    print(handler({"name": "Oblak"}))
