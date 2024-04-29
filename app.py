from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_mysqldb import MySQL
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'user_db'
mysql = MySQL(app)


# Register route
@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User registered successfully'}), 201


# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), bytes(user[2], 'utf-8')):
        session['username'] = username
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


# Update route with userid parameter
@app.route('/update/<int:userid>', methods=['PUT'])
def update(userid):
    new_password = request.json['new_password']

    # Hash the new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_password, userid))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User password updated successfully'}), 200


# Delete route with userid parameter
@app.route('/delete/<int:userid>', methods=['DELETE'])
def delete(userid):

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE user_id = %s", (userid,))
    mysql.connection.commit()
    cur.close()

    session.pop('username', None)  # Remove username from session

    return jsonify({'message': 'User deleted successfully'}), 200



if __name__ == '__main__':
    app.run(debug=True)
