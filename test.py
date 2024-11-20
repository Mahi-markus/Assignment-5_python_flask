"""
A simple Flask app with a POST method to handle username and password.
"""

from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/", methods=["GET"])
def form():
    """
    Display the login form.
    """
    return render_template("form.html")


@app.route("/submit", methods=["POST"])
def submit():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    return f"Received username: {username} and password: {password}"


if __name__ == "__main__":
    app.run(debug=True)
