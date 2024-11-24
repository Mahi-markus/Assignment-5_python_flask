# Travel API with Microservices

This repository contains a **Travel API** built using **Python Flask** with a microservices architecture. The API manages user accounts, destinations, and authentication, all integrated with role-based access control. Swagger is used for API documentation and testing.

---

## Installation and Setup

### Prerequisites:

- Python 3.8+
- `pip` package manager
- Postman or any API client (optional, Swagger is included)

### Steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/Mahi-markus/Assignment-5_python_flask.git
   ```

   ```bash
   cd Assignment-5_python_flask
   ```

   Install dependencies:

```bash

pip install -r requirements.txt
```

Run each service:

### User Service (Port: 5002):

```bash
python user_service.py
```

### Destination Service (Port: 5001):

```bash
python destination_service.py
```

### Authorization Service (Port: 5003):

```bash
python auth_service.py
```

Access Swagger documentation:

### 1. User Service (Port: 5002)

Handles user-related operations, including login, registration, and profile management.

Endpoints:

### POST /register

Register a new user.
Request Body:

```bash

{
  "username": "string",
  "password": "string",
  "role": "User or Admin"
}
```

### POST /login

Authenticate a user and generate a token.
Request Body:

```bash
 "email": "admin2@gmail.com",
  "password": "string1234"
```

### GET /profile

Retrieve the profile of the currently authenticated user.
Headers:

```bash
Authorization: Bearer <token>
```

### GET /users

Retrieve all registered users (Admin only).
Headers:

```bash
Authorization: Bearer <token>
```

### 2. Destination Service (Port: 5001)

Destination Information:
Each destination includes:

id (integer): Unique identifier.
name (string): Name of the destination.
description (string): Detailed description of the destination.
location (string): Geographical location of the destination.
Endpoints:
GET /destinations
Retrieve all available destinations.
Response:

```bash

{
"id": "int",
"name": "string",
"description": "string",
"location": "string"
}

```

### POST /destinations

Add a new destination (Admin only).
Headers:
Authorization: Bearer <token>
Request Body:

json

```bash
{
"name": "string",
"description": "string",
"location": "string"
}
```

```bash
GET /destinations/<id>
```

Retrieve a destination by its ID.
Response:

json

```bash
{
"id": "int",
"name": "string",
"description": "string",
"location": "string"
}
```

### DELETE /destinations/<id>

Delete a destination by its ID (Admin only).
Headers:
Authorization: Bearer <token>

### 3. Authorization Service

Handles token-based authentication and validation.

Endpoints:

### POST /login

user just need to put token in the input in order to login

### POST /validate

User just need to put the token generated by login to Validate a token and retrieve role information.
for example:

```bash
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZjZlZWJhYzktOGVlMC00YWI0LTg5MjgtNDNhNTE2NGVmMWFhIiwicm9sZSI6IkFkbWluIiwiZXhwIjoxNzMyNTU4ODU5fQ.ZzyHji3wBi5w7NceRKcbzKM5aySr123mzFmkK1ZBKHQ
```

Response (for admin):

```bash
{
  "permissions": {
    "access_level": "full",
    "can_create_users": true,
    "can_delete_users": true,
    "can_modify_roles": true,
    "can_view_all_profiles": true
  },
  "role": "Admin",
  "status": "Token is valid",
  "token_validity": {
    "expiration": "2024-11-26T00:20:59",
    "valid_for": "29 hours, 54 minutes"
  },
  "user_id": "f6eebac9-8ee0-4ab4-8928-43a5164ef1aa"
}
```
