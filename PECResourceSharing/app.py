from flask import Flask,render_template,session,request,logging,url_for,flash,redirect
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from functools import wraps

app = Flask(__name__)

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='ead'
app.config['MYSQL_CURSORCLASS']='DictCursor'

mysql = MySQL(app)


@app.route('/')
def home():
  return render_template('home.html')

class RegisterForm(Form):
  name = StringField('Name',[validators.Length(min=1,max=50)])
  SID = StringField('SID', [validators.Length(min=8, max=8)])
  email = StringField('email', validators=[validators.Email()])
  Branch = StringField('Branch',[validators.Length(min=2,max=3)])
  password = PasswordField('Password',[
    validators.DataRequired(),validators.EqualTo('confirm',message='Passwords do not match')
    ])
  confirm = PasswordField('Confirm Password')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register',methods=['GET','POST'])
def register():


    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        SID = form.SID.data
        email = form.email.data
        Branch = form.Branch.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()

        x = cur.execute("SELECT * from users where sid = %s",(SID,))
        print(x)

        if cur.fetchone() is not None:
            flash('Student with same SID already registered','success')
            return redirect(url_for('register'))
        else:
            cur.execute("INSERT into users(name, sid, email, branch, password) VALUES(%s,%s,%s,%s,%s)",(name,SID,email,Branch,password))
            mysql.connection.commit()
            cur.close()
            flash("You are now registered and can log in","success")
            return redirect(url_for('login'))
    return render_template('register.html',form=form)



#user Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        sid = request.form['SID']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE SID = %s", (sid,))

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['SID'] = sid

                flash('You are now logged in', 'success')
                return redirect(url_for('branch'))
                '''
                if data['Branch']=='AERO":
                    return redirect('https://drive.google.com/drive/folders/1GzNnPO_XmOhvh6wxIMrK-TxnYF2Xr3bi?usp=sharing')
                if data['Branch']==CIVIL:
                    return redirect('https://drive.google.com/drive/folders/1dEdAk2yWhbNBjL4YmYvtuAi_xuKcYqoG?usp=sharing')
                if data['Branch']==CSE:
                    return redirect('https://drive.google.com/drive/folders/1upghKczf1qp21hFcSzPxI0zTluJoront?usp=sharing')
                if data['Branch']==ECE:
                    return redirect('https://drive.google.com/drive/folders/1jqVbpmva5P72qVSbrFCHCLwLBzWkjK64?usp=sharing')
                if data['Branch']==EE:
                    return redirect('https://drive.google.com/drive/folders/1V5erOHyosHtbwjPtRlEtDNpULFEDkZDg?usp=sharing')
                if data['Branch']==MECH:
                    return redirect('https://drive.google.com/drive/folders/1VplunLFMFN5mjIMiX_cUuwRdp9-FK4XJ?usp=sharing')
                if data['Branch']==META:
                    return redirect('https://drive.google.com/drive/folders/1UlyOeyzBz0vdnCryOybl9E3Wa4hpl83L?usp=sharing')
                if data['Branch']==PROD:
                    return redirect('https://drive.google.com/drive/folders/1yMECPQXQlqrLaD4xWXpf_7nkpFa0R0Yh?usp=sharing')
                '''
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/branch')
def branch():
    return  render_template('branch.html')

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))



if __name__=='__main__':
    app.secret_key="123"
    app.run(debug=True)
