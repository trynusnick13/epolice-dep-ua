import hashlib
import os
import pickle
import re
from datetime import datetime

import pymongo
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from bson.objectid import ObjectId
from flask import render_template, redirect, request, flash, url_for, session, send_file
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
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
    return render_template('index.html')


@app.route('/index1')
def index1():
    return render_template('index1.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/uploads', methods=['GET', 'POST'])
def download():
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

        lemmatizer = WordNetLemmatizer()
        stop_words = set(stopwords.words('english'))
        word_tokens = word_tokenize(application)
        filtered_sentence = [w for w in word_tokens if not w in stop_words]
        singles = ' '.join([lemmatizer.lemmatize(plural).upper() for plural in filtered_sentence])

        loaded_model = pickle.load(open('classifiers/finalized_model.sav', 'rb'))
        pred = loaded_model.predict([singles])
        pred = int(pred[0])

        if pred == 0:
            result = 'GAMBLING'
        elif pred == 1:
            result = 'HUMAN TRAFFICKING'
        elif pred == 2:
            result = 'NON-CRIMINAL'
        elif pred == 3:
            result = 'PUBLIC INDECENCY'
        elif pred == 4:
            result = 'NARCOTICS'
        elif pred == 5:
            result = 'NON-CRIMINAL (SUBJECT SPECIFIED)'
        elif pred == 6:
            result = 'MOTOR VEHICLE THEFT'
        elif pred == 7:
            result = 'DECEPTIVE PRACTICE'
        elif pred == 8:
            result = 'OTHER OFFENSE'
        elif pred == 9:
            result = 'THEFT'
        elif pred == 10:
            result = 'HOMICIDE'
        elif pred == 11:
            result = 'ARSON'
        elif pred == 12:
            result = 'PUBLIC PEACE VIOLATION'
        elif pred == 13:
            result = 'INTIMIDATION'
        elif pred == 14:
            result = 'CONCEALED CARRY LICENSE VIOLATION'
        elif pred == 15:
            result = 'PROSTITUTION'
        elif pred == 16:
            result = 'CRIM SEXUAL ASSAULT'
        elif pred == 17:
            result = 'KIDNAPPING'
        elif pred == 18:
            result = 'STALKING'
        elif pred == 19:
            result = 'OTHER NARCOTIC VIOLATION'
        elif pred == 20:
            result = 'BATTERY'
        elif pred == 21:
            result = 'ASSAULT'
        elif pred == 22:
            result = 'BURGLARY'
        elif pred == 23:
            result = 'CRIMINAL TRESPASS'
        elif pred == 24:
            result = 'ROBBERY'
        elif pred == 25:
            result = 'INTERFERENCE WITH PUBLIC OFFICER'
        elif pred == 26:
            result = 'CRIMINAL DAMAGE'
        elif pred == 27:
            result = 'OFFENSE INVOLVING CHILDREN'
        elif pred == 28:
            result = 'SEX OFFENSE'
        elif pred == 29:
            result = 'OBSCENITY'
        elif pred == 30:
            result = 'NON - CRIMINAL'
        elif pred == 31:
            result = 'WEAPONS VIOLATION'
        elif pred == 32:
            result = 'LIQUOR LAW VIOLATION'
        else:
            result = 'OTHER'

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
    if request.method == 'POST':
        f = request.files['file']

        f.save(os.path.join('app/static', secure_filename(session['username'] + '.png')))
        db.update_one({'username': session['username'], 'password': session['password']},
                      {"$set": {"photo": 'static/' + session['username'] + '.png'}})
        flash('You updated the photo!')
    return redirect('/profile')


@app.route('/check_precinct')
def check_precinct():
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
        print(applic.find_one({'_id': id})['sessionkey'])
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
                          {"$set": {'check': None, 'level': 'worker3',
                                    'sessionkey': sessionkey, 'application': ciphertext, 'signature': sig,
                                    'publickey1': db.find_one({'username': session['username']})['publickey']}})

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
    investigator = "worker2.1"
    applic.update_one({'application': text}, {"$set": {'level': investigator, 'check': None}})
    flash("You sent application to investigator!")
    return redirect('/profile')


@app.route('/login/', methods=["GET", "POST"])
def login():
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

        if (re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$', password)):
            pass
        else:
            flash('Password is not strong enough! Try again!')
            return redirect(url_for('register_page'))

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

        flash('Thanks for registering')
        return redirect('/profile')

    return render_template("register.html", form=form)
