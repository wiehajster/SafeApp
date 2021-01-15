#from flask_blog import db
#db.create_all()

from flask_blog import app

if __name__=='__main__':
    app.run(debug=True)