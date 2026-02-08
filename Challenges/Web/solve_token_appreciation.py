import jwt
import base64

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmbGFnIjoiY3J5cHRve2p3dF9jb250ZW50c19jYW5fYmVfZWFzaWx5X3ZpZXdlZH0iLCJ1c2VyIjoiQ3J5cHRvIE1jSGFjayIsImV4cCI6MjAwNTAzMzQ5M30.shKSmZfgGVvd2OSB2CGezzJ3N6WAULo3w9zCl_T47KQ"


# Split by "."
parts = token.split(".")

# Decode each part
for idx, part in enumerate(parts):
    # Pad the base64 string if needed
    padded = part + '=' * (-len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
    print(f"Part {idx + 1} (decoded):\n{decoded}\n")