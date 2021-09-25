This is a simple Flas API app

POST /login -> returns JWT token.
GET /run -> validates the JWT token in the Header Authorization and returns "Hello World" on authenticated request. If you like to make this do something more, eg. execute some API, feel free to do so.
GET /me -> validates the JWT token, and returns the extracted values from the token.

Steps to start the app:

    1. docker build -t flask-jwt-app
    2. docker run -p 5000:5000 flask-jwt-app

Credentials for testing:

username: testuser
password: 123456