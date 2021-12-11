import hashlib
import logging
import os
import re
from datetime import datetime

import pymongo
import requests
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from bson.objectid import ObjectId
from flask import render_template, redirect, request, flash, url_for, session, send_file
from werkzeug.utils import secure_filename

from app import app
from app.forms import LoginForm, RegistrationForm, ApplicationForm
from app.locations import lc

db_main = pymongo.MongoClient(
    "mongodb+srv://police-dep:11111@cluster0.w7nvt.mongodb.net/users?ssl=true&ssl_cert_reqs=CERT_NONE"
)
db = db_main["users"]
db = db["users"]
settings = db_main['settings']
settings = settings['settings']
applic = db_main['applications']
applic = applic['applications']


@app.route('/')
@app.route('/index')
def index():
    user_name = session.get("username")
    logging.info("%s On index page (/index)", user_name if user_name else "Guest")
    return render_template('index.html')


@app.route('/index1')
def index1():
    user_name = session.get("username")
    logging.info("%s On index page (/index1)", user_name if user_name else "Guest")
    return render_template('index1.html')


@app.route('/contact')
def contact():
    user_name = session.get("username")
    logging.info("%s On contact page (/contact)", user_name if user_name else "Guest")
    return render_template('contact.html')


@app.route('/uploads', methods=['GET', 'POST'])
def download():
    user_name = session.get("username")
    logging.info("%s Downloads template (/uploads)", user_name if user_name else "Guest")
    return send_file('files/application_templates.pdf', as_attachment=True)


@app.route('/same_applications')
def same_applications():
    cat = request.args.get('cat')

    data_app = applic.find({})
    your = list()
    same = list()
    for data in data_app:
        if data['classifier'] == cat:
            same.append(data)
        if (data['level'] == session['rank']) and (data['check'] == session['username']):
            your.append(data)

    return render_template('same_applications.html', new=your, same=same)


@app.route('/database')
def database():
    user_name = session.get("username")
    logging.info("%s is looking for all the cases (/database)", user_name if user_name else "Guest")
    data_app = applic.find({})
    open = list()
    finished = list()
    closed = list()
    for data in data_app:
        if data['status'] == 'Open':
            open.append(data)
        elif data['status'] == 'Finished':
            finished.append(data)

    return render_template('database.html', open=open, finished=finished, closed=closed)


@app.route('/application', methods=["GET", "POST"])
def applications():
    user_name = session.get("username")
    logging.info("%s Applies the application (/application)", user_name if user_name else "Guest")
    form = ApplicationForm(request.form)
    if request.method == "POST":
        first_name = form.first_name.data
        second_name = form.second_name.data
        phone = form.phone.data
        locations = request.form.getlist('loc')
        application = form.application.data
        created = datetime.utcnow()
        level = 'worker1'
        history = []
        check = None
        status = 'Not reviewed'

        response = requests.post(
            "https://nlp-police-department-service.herokuapp.com/application",

            json={
                'application': application,
            }
        )
        result = response.json().get("result", "")

        applic_id = applic.insert_one({
            'first_name': first_name,
            'second_name': second_name,
            'phone': phone,
            'locations': locations,
            'application': application,
            'classifier': result,
            'created': created,
            'level': level,
            'history': history,
            'check': check,
            'status': status,
            'evidence': ''
        })

        flash('Thanks for application!')
        return redirect('/index')
    return render_template('application.html', form=form, locations=lc)


@app.route('/profile', methods=["GET", "POST"])
def profile():
    user_name = session.get("username")
    logging.info("%s On profile page (/profile)", user_name if user_name else "Guest")
    try:
        data_main = db.find({'username': session['username'],
                             'password': session['password']})

        error = None
        precinct = None
        investigator = None
        prosecutor = None

        data_app = applic.find({})
        new = list()
        your = list()
        for data in data_app:
            if (data['level'] == session['rank']) and (data['check'] == None):
                new.append(data)
            elif (data['level'] == session['rank']) and (data['check'] == session['username']):
                your.append(data)

        if session['rank'] == 'worker1':
            precinct = True
        elif session['rank'] == 'worker2.1' or session['rank'] == 'worker2.2' or session['rank'] == 'worker2.3':
            investigator = True
        elif session['rank'] == 'worker3':
            prosecutor = True

        edit = request.args.get('edit')
        if edit == 'True':
            form = True

        else:
            form = None


    except:
        data_main = None
        error = True
        new = None
        your = None
        precinct = None
        investigator = None
        prosecutor = None
        form = None

    return render_template('profile.html', data=data_main, error=error, new=new, your=your, precinct=precinct,
                           investigator=investigator, prosecutor=prosecutor, form=form)


@app.route('/photo', methods=["GET", "POST"])
def photo():
    user_name = session.get("username")
    logging.info("%s Updates photo (/photo)", user_name if user_name else "Guest")
    if request.method == 'POST':
        f = request.files['file']

        f.save(os.path.join('app/static', secure_filename(session['username'] + '.png')))
        db.update_one({'username': session['username'], 'password': session['password']},
                      {"$set": {"photo": 'static/' + session['username'] + '.png'}})
        flash('You updated the photo!')
    return redirect('/profile')


@app.route('/check_precinct')
def check_precinct():
    user_name = session.get("username")
    logging.info("%s Check precinct photo (/check_precinct)", user_name if user_name else "Guest")
    text = request.args.get('text')
    id = ObjectId(request.args.get('id'))
    if session['rank'] == 'worker1':
        applic.update_one({'application': text},
                          {"$set": {"history": [session['username']], 'check': session['username']}})
    elif session['rank'] == 'worker2.1' or session['rank'] == 'worker2.2' or session['rank'] == 'worker2.3':
        for line in applic.find({'application': text}):
            history = line['history']
            applic.update_one({'application': text},
                              {"$set": {"history": history + [session['username']], 'check': session['username'],
                                        'status': 'Open'}})
    elif session['rank'] == 'worker3':
        privatekey = RSA.importKey(db.find_one({'rank': 'worker3'})['privatekey'])
        cipherrsa = PKCS1_OAEP.new(privatekey)
        logging.info(applic.find_one({'_id': id})['sessionkey'])
        print(type(applic.find_one({'_id': id})['sessionkey']))
        sessionkey = cipherrsa.decrypt(applic.find_one({'_id': id})['sessionkey'])
        ciphertext = applic.find_one({'_id': id})['application']
        iv = ciphertext[:16]
        obj = AES.new(sessionkey, AES.MODE_CFB, iv)
        plaintext = obj.decrypt(ciphertext)
        plaintext = plaintext[16:]
        plaintext = bytes(plaintext)
        signature = applic.find_one({'_id': id})['signature']
        sig = cipherrsa.decrypt(signature[:256])
        sig = sig + cipherrsa.decrypt(signature[256:])
        publickey = RSA.importKey(applic.find_one({'_id': id})['publickey1'])
        myhash = SHA.new(plaintext)
        signature = PKCS1_v1_5.new(publickey)
        test = signature.verify(myhash, sig)
        for line in applic.find({'_id': id}):
            history = line['history']
            applic.update_one({'_id': id},
                              {"$set": {'history': history + [session['username']], 'check': session['username'],
                                        'status': 'Open',
                                        'application': str(plaintext)[2:-1]}})
    flash('You approved the application!')
    return redirect('/profile')


@app.route('/send_precinct')
def send_precinct():
    id = ObjectId(request.args.get('id'))
    text = request.args.get('text')
    if session['rank'] == 'worker2.1' or session['rank'] == 'worker2.2' or session['rank'] == 'worker2.3':
        privatekey = RSA.importKey(db.find_one({'username': session['username']})['privatekey'])
        myhash = SHA.new(bytes(text, encoding='ascii'))
        signature = PKCS1_v1_5.new(privatekey)
        signature = signature.sign(myhash)
        publickey = RSA.importKey(db.find_one({'rank': 'worker3'})['publickey'])
        cipherrsa = PKCS1_OAEP.new(publickey)
        sig = cipherrsa.encrypt(signature[:128])
        sig = sig + cipherrsa.encrypt(signature[128:])
        sig = bytes(sig)
        sessionkey = Random.new().read(32)
        iv = Random.new().read(16)
        obj = AES.new(sessionkey, AES.MODE_CFB, iv)
        ciphertext = iv + obj.encrypt(bytes(text, encoding='ascii'))
        ciphertext = bytes(ciphertext)
        sessionkey = cipherrsa.encrypt(sessionkey)
        sessionkey = bytes(sessionkey)
        applic.update_one({'application': text},
                          {"$set":

                               {'check': None,
                                'level': 'worker3',
                                'sessionkey': sessionkey,
                                'application': ciphertext,
                                'signature': sig,
                                'publickey1': db.find_one({'username': session['username']})['publickey']
                                }
                           }
                          )

        flash('You sent the application!')

    elif session['rank'] == 'worker3':
        applic.update_one({'_id': id}, {"$set": {'check': None, 'level': 'end', 'status': 'Finished'}})
        flash('You finished this case!')
    return redirect('/profile')


@app.route('/delete')
def delete():
    id = ObjectId(request.args.get('id'))
    applic.delete_one({'_id': id})
    flash("You deleted the application!")
    return redirect('/profile')


@app.route('/delete1')
def delete1():
    id = ObjectId(request.args.get('id'))
    applic.delete_one({'_id': id})
    flash("You deleted the application!")
    return redirect('/database')


@app.route('/close')
def close():
    id = ObjectId(request.args.get('id'))
    applic.update_one({'_id': id}, {"$set": {'check': None, 'level': 'worker1', 'status': 'Open'}})
    flash("You returned the case!")
    return redirect('/profile')


@app.route('/choose_investigator')
def choose_investigator():
    text = request.args.get('text')
    investigator = request.args.get('investigator')
    applic.update_one({'application': text}, {"$set": {'level': investigator, 'check': None}})
    flash("You sent application to investigator!")
    return redirect('/profile')


@app.route('/login/', methods=["GET", "POST"])
def login():
    user_name = session.get("username")
    logging.info("%s Log in", user_name if user_name else "Guest")
    form = LoginForm(request.form)
    if request.method == "POST":
        username = form.username.data
        session['username'] = form.username.data
        password = hashlib.md5(str(form.password.data).encode()).hexdigest()
        session['password'] = str(password)

        query = db.find({'username': username,
                         'password': password})

        for data in query:
            session['rank'] = data['rank']

            if data['username']:
                logging.info("%s Successfully log in", data['username'])
                return redirect('/profile')
            else:
                flash("Invalid username/password")
                return redirect(url_for('login'))

    return render_template('login.html', title='Sign In', form=form)


@app.route('/evidence', methods=["GET", "POST"])
def evidence():
    id = ObjectId(request.args.get('id'))
    if request.method == "POST":
        ev = request.form['evidence']

        applic.update_one({'_id': id}, {"$set": {'evidence': applic.find_one({'_id': id})['evidence'] + ', ' + ev}})
        return redirect(url_for('profile'))


@app.route('/logout/')
def logout():
    session.pop('username', None)
    session.pop('password', None)
    session.pop('rank', None)
    flash('You logout from account!')
    return redirect(url_for('index'))


@app.route('/register/', methods=["GET", "POST"])
def register_page():
    user_name = session.get("username")
    logging.info("%s Log in", user_name if user_name else "Guest")
    form = RegistrationForm(request.form)
    if request.method == "POST":
        username = form.username.data
        query = db.find({'username': username})
        for data in query:
            if username == data['username']:
                flash('Sorry, but username is already taken! Try again!')
                return redirect(url_for('register_page'))
            else:
                break
        email = form.email.data
        query = db.find({'email': email})
        for data in query:
            if email == data['email']:
                flash('Sorry, but email is already taken! Try again!')
                return redirect(url_for('register_page'))
            else:
                break

        if (re.match(r'\S+@\S+', email)):
            pass
        else:
            flash('Invalid email address! Try again!')
            return redirect(url_for('register_page'))

        password = form.password.data
        confirm = form.confirm.data

        if password == confirm:
            pass
        else:
            flash('Passwords must match! Try again!')
            return redirect(url_for('register_page'))

        # if (re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$', password)):
        #     pass
        # else:
        #     flash('Password is not strong enough! Try again!')
        #     return redirect(url_for('register_page'))

        password = str(hashlib.md5(str(password).encode()).hexdigest())
        created = datetime.utcnow()
        admin = False
        key = form.key.data
        query = settings.find({})

        for data in query:
            if key in data.values():
                index = list(data.values()).index(key)
                keys = list(data.keys())[index]
                rank = keys
                session['rank'] = rank
                if rank == 'worker1':
                    rank_show = 'Precinct'
                elif rank == 'worker3':
                    rank_show = 'Prosecutor'
                    query1 = db.find_one({'rank': rank})
                    print(query1)
                    if query1:
                        flash('Sorry, the prosecutor is already registered!')
                        return redirect(url_for('register_page'))
                elif rank == 'worker2.1':
                    rank_show = 'Killing Investigator'
                elif rank == 'worker2.2':
                    rank_show = 'Theft Investigator'
                elif rank == 'worker2.3':
                    rank_show = 'Abduction Investigator'
                break
        else:
            flash('Key entered incorrectly! Contact the main office to confirm the validity of the key!')
            return redirect(url_for('register_page'))
        session['username'] = username
        session['password'] = password

        privatekey = RSA.generate(2048)
        publickey = privatekey.publickey()

        photo = '/static/unnamed.png'

        user_id = db.insert_one({
            'username': username,
            'photo': photo,
            'rank': rank,
            'rank_show': rank_show,
            'email': email,
            'password': password,
            'created': created,
            'privatekey': bytes(privatekey.exportKey('PEM')),
            'publickey': bytes(publickey.exportKey('PEM'))
        })
        logging.info("%s successfully registered", username)
        flash('Thanks for registering')
        return redirect('/profile')

    return render_template("register.html", form=form)
