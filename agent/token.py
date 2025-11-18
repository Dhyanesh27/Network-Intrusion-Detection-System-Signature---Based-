import jwt
import time

# Generate a JWT token using the backend's default secret
JWT_SECRET = 'dev-secret'  # This matches the backend's default in server.js

# Create a token payload
payload = {
    'agent_id': 'python-agent-1',  # Unique ID for this agent
    'iat': int(time.time()),  # Issued at
    'exp': int(time.time()) + 24*60*60  # Expires in 24 hours
}

try:
    # Generate the token (ensure it's a string)
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    print("Generated JWT Token:")
    print(token)

    # Print a ready-to-run agent command with the token embedded
    cmd = f'python agent.py --backend http://localhost:4000 --jwt-token "{token}"'
    print("\nRun the agent with the following command:")
    print(cmd)
except Exception as e:
    print("Failed to generate token:", str(e))
