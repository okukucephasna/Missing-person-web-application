from flask import*
import pymysql
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = 'secret'

# MySQL configuration
connection = pymysql.connect(host='localhost', user='root', password='',
                                             database='missing_persons')


@app.route('/')
def index():
    if 'logged_in' in session and session['logged_in']:
        return redirect('/dashboard')
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = sha256_crypt.encrypt(request.form['password'])

        cur = connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))
        connection.commit()
        cur.close()

        session['logged_in'] = True
        session['username'] = username

        return redirect('/dashboard')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            user = cur.fetchone()
            password_index = None
            for i, column in enumerate(cur.description):
                if column[0] == 'password':
                    password_index = i
                    break

            if password_index is not None:
                stored_password = user[password_index]

                if sha256_crypt.verify(password_candidate, stored_password):
                    session['logged_in'] = True
                    session['username'] = username

                    return redirect('/dashboard')
                else:
                    error = 'Invalid login'
                    return render_template('login.html', error=error)
            else:
                error = 'Password column not found'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

        cur.close()

    return render_template('login.html')







@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session and session['logged_in']:
        cur = connection.cursor()
        result = cur.execute("SELECT * FROM persons WHERE username = %s", [session['username']])

        if result > 0:
            missing_persons = cur.fetchall()
            return render_template('dashboard.html', missing_persons=missing_persons)

        cur.close()

        return render_template('dashboard.html')

    return redirect('/login')


@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'logged_in' in session and session['logged_in']:
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']

            cur = connection.cursor()
            cur.execute("INSERT INTO persons(name, description, username) VALUES(%s, %s, %s)",
                        (name, description, session['username']))
            connection.commit()
            cur.close()

            return redirect('/dashboard')

        return render_template('add.html')

    return redirect('/login')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
