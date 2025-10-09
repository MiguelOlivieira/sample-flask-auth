from database import db
from flask_login import UserMixin

                    #Herda metodos do userMixin
class User(db.Model, UserMixin): #Model que faz parte do proprio SQLAlchemy
    #id(int), username(text), password(text)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True) #Coluna obrigatoria e unica
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='user')
    
    #flask shell
    #db.create_all()
    #db.session.commit()
    #exit()
