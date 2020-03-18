#!/usr/bin/env python3
import os
import sys
import string
import random
import hashlib
import sqlite3

from websocket import create_connection
import requests


LOG = 1
PORT = 8080

DBNAME = "tavern.db"

CODES = {'OK': 101, 'CORRUPT': 102, 'MUMBLE': 103, 'DOWN': 104, 'CHECKER_ERROR': 110}

SHIT = {'conn':          ("Unable to connect to the service", CODES['DOWN']),
        'prot':          ("Server doenst answers properly", CODES['MUMBLE']),
        'allok':         ("Everything is fine", CODES['OK']),
        'flggg':         ("Wrong flag", CODES['CORRUPT']),
        'wtf':           ("Man, you should correct your checker", CODES['CHECKER_ERROR']),
       }

def check(hostname):
    flag = _gen_secret()

    username = _gen_random_string()
    password = _gen_random_string()

    try:
        s = requests.Session()
        s.post('http://' + hostname + '/signup', data={'username': username,
                                                       'password': password})
        resp = s.post('http://' + hostname + '/auth', data={'username': username,
                                                            'password': password})
        if not resp.status_code == 200 or not resp.url.endswith('/bar'):
            _die('prot')
        resp = s.post('http://' + hostname + '/addRecipe', data={'recipe': flag})
        if not resp.status_code == 200 or not resp.url.endswith('/recipes'):
            _die('prot')
        resp = s.get('http://' + hostname + '/recipes')
        if flag not in resp.text:
            _die('flggg')
    except requests.exceptions.ConnectionError:
        _die('conn')

    try:
        create_connection('ws://' + hostname)
    except:
        _die('prot')
    
    _die('allok')

def put(hostname, fid, flag):
    username = fid
    password = _gen_random_string()

    try:
        s = requests.Session()
        s.post('http://' + hostname + '/signup', data={'username': username,
                                                       'password': password})
        resp = s.post('http://' + hostname + '/auth', data={'username': username,
                                                            'password': password})
        if not resp.status_code == 200 or not resp.url.endswith('/bar'):
            _die('prot')
        resp = s.post('http://' + hostname + '/addRecipe', data={'recipe': flag})
        if not resp.status_code == 200 or not resp.url.endswith('/recipes'):
            _die('prot')
        _log('Get flag id: "{}"'.format(password))
        _save_id(fid, password)
    except requests.exceptions.ConnectionError:
        _die('conn')

    _die('allok')

def get(hostname, fid, flag):
    username = fid
    password = _get_pass(fid)
    try:
        s = requests.Session()
        resp = s.post('http://' + hostname + '/auth', data={'username': username,
                                                                   'password': password})
        if not resp.status_code == 200 or not resp.url.endswith('/bar'):
            _die('prot')

        resp = s.get('http://' + hostname + '/recipes')
        if flag not in resp.text:
            _die('flggg')
    except requests.exceptions.ConnectionError:
        _die('conn')
    _die('allok')

def _get_pass(fid):
    db = get_db()
    c = db.cursor()
    query = '''
                SELECT password FROM ids
                WHERE flagid = ?
                '''
    c.execute(query, (fid,))
    password = c.fetchone()[0]
    return password

def _save_id(flag_id, given_id):
    db = get_db()
    c = db.cursor()
    query = '''
            INSERT INTO ids(flagid, password)
            VALUES (?,?)
            '''
    c.execute(query, (flag_id, given_id,))
    db.commit()

def _log(t):
    if LOG:
        print(t)
    return t

def _die(event):
    assert event in SHIT
    msg, code = SHIT[event]
    _log(msg)
    sys.exit(code)

def get_db():
    return sqlite3.connect(DBNAME)

def prepare_db():
    db = get_db()
    c = db.cursor()
    cmd = '''
            CREATE TABLE IF NOT EXISTS
            ids(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flagid TEXT,
                password TEXT
            )
        '''
    c.execute(cmd)
    db.commit()

def _gen_secret():
    templates = ["I hide my {} in my {}", "I love to put {} into {}", "Do you also like {} when you are in {}"]
    places = ["hole", "secret place", "bed", "kitchen", "work", "garden"]
    items = ["fish", "dog", "secrets", "candies", "cookie", "talala"]
    template = random.choice(templates)
    return template.format(
        random.choice(items),
        random.choice(places)
    )

def _gen_random_string():
    return os.urandom(10).hex()

def main():
    prepare_db()
    get_db()
    cmd = sys.argv[1]
    hostname = sys.argv[2] + ':' + str(PORT)
    if cmd == 'get':
        fid = sys.argv[3]
        flag = sys.argv[4]
        return get(hostname, fid, flag)
    elif cmd == 'put':
        fid = sys.argv[3]
        flag = sys.argv[4]
        return put(hostname, fid, flag)
    elif cmd == 'check':
        return check(hostname)
    else:
        return die('wtf')

if __name__=="__main__":
    main()

