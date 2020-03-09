var Cookies = require('cookies')
var qs   = require('querystring');
var fs   = require('fs');
var path = require('path');

var MongoClient = require("mongodb").MongoClient

var mongoClient = new MongoClient("mongodb://database:27017/", { useNewUrlParser: true });

var jwt  = require('jsonwebtoken');
var secret = process.env.JWT_SECRET || "CHANGE_THIS_TO_SOMETHING_RANDOM"; // super secret

function loadView(view) {
  var filepath = path.resolve(__dirname, '../views/', view + '.html');
  return fs.readFileSync(filepath).toString();
}

// Content
var index      = loadView('index');      // default page
var restricted = loadView('restricted'); // only show if JWT valid
var admin      = loadView('admin');      // only show if JWT valid and the role is admin
var fail       = loadView('fail');       // auth fail
var signup     = loadView('signup');     // signup page

// Roles
const adminRole = 'Admin'
const userRole = 'User'

// show fail page (login)
function authFail(res, callback) {
  res.writeHead(401, {'content-type': 'text/html'});
  return res.end(fail);
}

// create JWT
function generateToken(req, opts, user) {
  opts = opts || {};

  // By default, expire the token after 7 days.
  // NOTE: the value for 'exp' needs to be in seconds since
  // the epoch as per the spec!
  var expiresDefault = '7d';

  var token = jwt.sign({
    name: user['name'],
    role: user['role']
  }, secret, { expiresIn: opts.expires || expiresDefault });

  return token;
}

function generateAndStoreToken(req, opts, user) {
  var token  = generateToken(req, opts, user);
  return token;
}

function authSuccess(req, res, user) {
  var token = generateAndStoreToken(req, null, user);

  var cookies = new Cookies(req, res)
  cookies.set('token', token)
  res.writeHead(302, {
    'Location': '/private'
  });
  return res.end(admin);
}


// handle authorisation requests
function authHandler(req, res){
  if (req.method === 'POST') {
    var body = '';
    req.on('data', function (data) {
      body += data;
    }).on('end', function () {
      var post = qs.parse(body);
      console.log("trying to connect...")

      mongoClient.connect(function(err, client) {
        if(err) {
            return console.log(err);
        }

        let user = {name: post.username}
        console.log("Connection is established with mongo db");

        db = client.db("BAR");
        db.collection("users").findOne(user, function(err, u) {
          if (err) throw err;

          console.log("user in db:", u)

          if (u ===  null) {
            return authFail(res);
          } 

          if (
            post.username && post.username === u.name && 
            post.password && post.password === u.password) {
              console.log("I know this user!");
              return authSuccess(req, res, u);
          }
          console.log("Invalid credinals!");
          return authFail(res);
        });
      });
    });
  } else {
    return res.end(index)
  };
}

function signupHandler(req, res) {
  if (req.method === 'POST') {
    var body = '';
    req.on('data', function (data) {
      body += data;
    }).on('end', function () {
      var post = qs.parse(body);

      mongoClient.connect(function(err, client) {
        if(err){
            return console.log(err);
        }
        const db = client.db("BAR");
        const collection = db.collection("users");
        let user = {name: post.username, password: post.password, role: userRole}
        console.log("new user", user)

        collection.insertOne(user, function(err, result) {
          if(err){ 
              return console.log("insrtion error:", err);
          }
          console.log("insert OK!");
        });
      });

      res.writeHead(302, {
        'Location': '/auth'
      });

    });
  } else {
    return res.end(signup)
  }
}

function verify(token) {
  var decoded = false;
  jwt.verify(token, secret, function (err, payload) {
    if (err) {
      decoded = false; // still false
    } else {
      decoded = payload;
    }
  });
  return decoded;
}

// can't use the word private as its an ES "future" reserved word!
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#Keywords
function privado(res, token, role) {
  res.writeHead(200, {
    'content-type': 'text/html'
  });
  if (role === 'user') {
    return res.end(restricted);
  } else {
    return res.end(admin);
  }
}

function validate(req, res, callback) {
  var cookies = new Cookies(req, res)
  var token = cookies.get('token')
  var decoded = verify(token);
  if(!decoded || !decoded.auth) {
    authFail(res);
    return callback(res);
  } else {
    db.get(decoded.auth, function (err, record) {
      var r;
      try {
        r = JSON.parse(record);
      } catch (e) {
        r = { valid : false };
      }
      if (err || !r.valid) {
        authFail(res);
        return callback(res);
      } else {
        privado(res, token, decoded.role);
        return callback(res);
      }
    });
  }
}

function notFound(res) {
  res.writeHead(404, {'content-type': 'text/plain'});
  return res.end('404 Not Found');
}

function home(res) {
  res.writeHead(200, {'content-type': 'text/html'});
  return res.end(index);
}

function done(res) {
  return; // does nothing. (pass as callback)
}

function logout(req, res, callback) {
  // invalidate the token
  var cookies = new Cookies(req, res);
  var token = cookies.get('token');
  var decoded = verify(token);
  if(decoded) { // otherwise someone can force the server to crash by sending a bad token!
    // asynchronously read and invalidate
    db.get(decoded.auth, function(err, record) {
      if (!err) {
        var updated    = JSON.parse(record);
        updated.valid  = false;
        db.put(decoded.auth, updated, function (err) {
          // console.log('updated: ', updated)
        });
      }
      cookies.set('token');
      res.writeHead(302, {
        'Location': '/'
      });
      res.end();
      return callback(res);
    });
  } else {
    cookies.set('token');
    authFail(res, done);
    return callback(res);
  }
}


module.exports = {
  fail : authFail,
  done: done, // moch callback
  home: home,
  handler : authHandler,
  signup: signupHandler,
  logout : logout,
  notFound : notFound,
  success : authSuccess,
  validate : validate,
  verify : verify,
  view : loadView,
  generateAndStoreToken: generateAndStoreToken
}
