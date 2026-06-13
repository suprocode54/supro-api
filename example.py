"""Example SuproAPI application."""

from supro_api import SuproAPI, Request, Response

app = SuproAPI("MyAPI")
app.configure_jwt(secret_key="your-secret-key-change-this")


@app.before_request
def auth_check(request: Request):
    """Middleware: check auth for protected routes."""
    if request.path.startswith("/api/"):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token and app.jwt:
            return Response().json({"error": "Unauthorized"}, status=401)


@app.get("/")
def index(request: Request, response: Response):
    """Root endpoint."""
    return response.json({"message": "Welcome to MyAPI!", "version": "1.0.0"})


@app.get("/api/users")
def get_users(request: Request, response: Response):
    """Get all users."""
    users = [
        {"id": 1, "name": "SuproCode", "role": "admin"},
        {"id": 2, "name": "Developer", "role": "user"},
    ]
    return response.json({"users": users, "count": len(users)})


@app.post("/api/users")
def create_user(request: Request, response: Response):
    """Create a new user."""
    if not request.json:
        return response.json({"error": "Invalid JSON"}, status=400)
    return response.json({"message": "User created", "user": request.json}, status=201)


@app.get("/api/users/{user_id}")
def get_user(request: Request, response: Response):
    """Get user by ID."""
    user_id = request.params.get("user_id")
    return response.json({"user_id": user_id, "name": f"User {user_id}"})


@app.get("/docs")
def docs(request: Request, response: Response):
    """API documentation."""
    return response.json(app.get_docs())


if __name__ == "__main__":
    app.run(debug=True)
