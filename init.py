from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///influencer.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'Y0GWd3qguSb4Jdbzo2pQmS7thiklShvv'
db = SQLAlchemy(app)  
migrate = Migrate(app, db)  

