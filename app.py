from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger
from flasgger.utils import swag_from
from flasgger import LazyString, LazyJSONEncoder
from functools import wraps
import jwt 
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 

app = Flask(__name__)
app.config["SWAGGER"] = {"title": "Swagger-UI", "uiversion": 2}

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec_1",
            "route": "/apispec_1.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger/",
}

template = dict(
    swaggerUiPrefix=LazyString(lambda: request.environ.get("HTTP_X_SCRIPT_NAME", ""))
)

app.json_encoder = LazyJSONEncoder
swagger = Swagger(app, config=swagger_config, template=template)

app.config['SECRET_KEY'] = 'thisisthesecretkey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   
migrate = Migrate(app, db)

class Users(db.Model):  
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)  
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})

@app.route('/run')
@swag_from("swag_conf/run_config.yml")
@token_required
def run():
    return jsonify({'message' : 'Hello World!'})

@app.route('/me')
@swag_from("swag_conf/me_config.yml")
@token_required
def me():
    token = request.args.get('token')
    try: 
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return jsonify({'message' : data})
    except:
        return jsonify({'message' : 'Token is invalid!'}), 403
    
@app.route('/login', methods=['POST'])
@swag_from("swag_conf/login_config.yml")
def login():
    username = request.args.get('name')
    print(username)
    password = request.args.get('password')
    print(password)
    if not username or not password: 
        return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})
    user = Users.query.filter_by(name=username).first() 
    if check_password_hash(user.password, password):
        token = jwt.encode({'user' : username, 
                            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token})

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
 data = request.get_json()  
 hashed_password = generate_password_hash(data['password'], method='sha256')
 new_user = Users(public_id=str(uuid.uuid4()), 
                  name=data['name'], 
                  password=hashed_password, 
                  admin=False) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})   

@app.route('/users', methods=['GET'])
@swag_from("swag_conf/users_config.yml")
def get_all_users():  
   
   users = Users.query.all() 
   result = []   
   for user in users:   
       user_data = {}   
       user_data['public_id'] = user.public_id  
       user_data['name'] = user.name 
       user_data['admin'] = user.admin 
       
       result.append(user_data)   
   return jsonify({'users': result})  

if __name__ == '__main__': 
    app.run(debug=True) 