/* Modules */
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken');
const express = require("express");
const http = require('http')
const WebSocket = require('ws')
const Cookies = require('cookies')
const {
    execSync
} = require('child_process');

/* MongoClient initialization */
var MongoClient = require("mongodb").MongoClient
var mongoClient = new MongoClient("mongodb://database:27017/", {
    useNewUrlParser: true
});

// Making usernames unique
mongoClient.connect(function(err, client) {
    if (err) {
        return console.log(err);
    }
    client.db("BAR").collection("users").createIndex({
        name: 1
    }, {
        unique: true
    }, function(err, result) {
        if (err) {
            console.log(err);

        } else {
            console.log(result);
        }
    });
});

/* Constants */
// Roles
const adminRole = 'Admin'
const userRole = 'User'

// Port
const port = 8080;

// JWT secret
const secret = process.env.JWT_SECRET || "CHANGE_THIS_TO_SOMETHING_RANDOM";
const seed = "104101108108111";

/* App initialization */
var app = express();
var router = express.Router();
var server = http.createServer(app);
var wss = new WebSocket.Server({
    server
})

app.set("view engine", "ejs");
app.use(express.static(__dirname + '/views'));
app.use(cookieParser());
app.use(express.urlencoded());
app.use('/', router);

server.listen(port);

/* SUPPA PUPPA service logic */
//      .
//        .
//    . ;.
//     .;
//      ;;.
//    ;.;;
//    ;;;;.
//    ;;;;;
//    ;;;;;
//    ;;;;;
//    ;;;;;
//    ;;;;;
//  ..;;;;;..
//   ':::::'
//     ':`

wss.on('connection', function connection(ws, req) {
    ws.on('message', function incoming(message) {
        var json = JSON.parse(message);
        if (json.cmd == 'get_name') {
            var decode = verify(json.token);
            if (decode) {
                ws.send(JSON.stringify({
                    "name": decode.name
                }));
            } else {
                ws.send(JSON.stringify({
                    "name": "strange person"
                }));
            }

        }
        if (json.cmd == 'get_recipe') {
            var name = json.name;
            if (name) {
                console.log('received: %s', message)
                mongoClient.connect(function(err, client) {
                    if (err) {
                        return console.log(err);
                    }

                    let owner = {
                        name: name
                    }

                    console.log("owner ", owner);

                    client.db("BAR").collection("recipes").find(owner).toArray(function(err, results) {
                        results.forEach(function(res) {
                            ws.send(JSON.stringify({
                                "recipes": res.recipe
                            }));
                        })
                    });
                });
            } else {
                ws.send('something')
            }
        }

    })
})


router.get("/", function(req, res, next) {
    var decoded = verify(req.cookies.token);
    console.log(decoded);
    if (!decoded) {
        res.writeHead(302, {
            'Location': '/auth'
        });
        return res.end();
    } else {
        res.writeHead(302, {
            'Location': '/bar'
        });
        return res.end();
    }
})


router.post("/signup", function(req, res, next) {
    mongoClient.connect(function(err, client) {
        if (err) {
            return console.log(err);
        }

        let user = {
            name: req.body.username,
            password: hash(req.body.password),
            role: userRole
        }
        console.log("new user", user)

        client.db("BAR").collection("users").insertOne(user, function(err, result) {
            if (err) {
                return console.log("insrtion error:", err);
            }
            console.log("insert OK!");
        });
    });

    res.writeHead(302, {
        'Location': '/auth'
    });
    return res.end();
})

router.get("/signup", function(req, res, next) {
    return res.render('signup');
})

router.post("/auth", function(req, res, next) {
    mongoClient.connect(function(err, client) {
        if (err) {
            return console.log(err);
        }

        let user = {
            name: req.body.username
        }

        client.db("BAR").collection("users").findOne(user, function(err, u) {
            if (err) {
                return console.log(err);
            }

            if (u === null) {
                return authFail(res);
            }

            if (
                req.body.username && req.body.username === u.name &&
                req.body.password && hash(req.body.password) === u.password) {
                console.log("I know this user!");
                return authSuccess(req, res, u);
            }

            return authFail(res);
        });
    });
})


router.get("/auth", function(req, res, next) {
    return res.render('index')
})

router.get("/recipes", function(req, res, next) {
    var decoded = verify(req.cookies.token);
    if (!decoded) {
        return authFail(res);
    } else {
        if (decoded.role === adminRole) {
            mongoClient.connect(function(err, client) {
                if (err) {
                    return console.log(err);
                }
                client.db("BAR").collection("recipes").find().toArray(function(err, results) {
                    return res.render('recipes', {
                        records: results
                    });
                });
            });
        } else {
            mongoClient.connect(function(err, client) {
                if (err) {
                    return console.log(err);
                }

                let owner = {
                    name: decoded.name
                }

                client.db("BAR").collection("recipes").find(owner).toArray(function(err, results) {
                    return res.render('recipes', {
                        records: results
                    });
                });
            });
        }
    }
})

router.post("/addRecipe", function(req, res, next) {
    var decoded = verify(req.cookies.token);
    if (!decoded) {
        authFail(res);
        return callback(res);
    }

    mongoClient.connect(function(err, client) {
        if (err) {
            return console.log(err);
        }

        let newRecipe = {
            name: decoded.name,
            recipe: req.body.recipe
        }

        client.db("BAR").collection("recipes").insertOne(newRecipe, function(err, result) {
            if (err) {
                return console.log("insrtion error:", err);
            }
            console.log("insertion recipe finished with OK!");
        });
        res.writeHead(302, {
            'Location': '/recipes'
        });
        return res.end();
    });
})

router.get("/addRecipe", function(req, res, next) {
    return res.render('addRecipe');
})

router.get("/bar", function(req, res, next) {
    var decoded = verify(req.cookies.token);
    if (!decoded) {
        res.writeHead(302, {
            'Location': '/auth'
        });
        return res.end();
    } else {
        mongoClient.connect(function(err, client) {
            if (err) {
                return console.log(err);
            }

            client.db("BAR").collection("users").find().toArray(function(err, results) {
                return res.render('bar', {
                    records: results
                });
            });
        });
    }
})

router.get("/logout", function(req, res, next) {
  var cookies = new Cookies(req, res);
  var token = cookies.get('token');
  // console.log(' >>> ', token)
  var decoded = verify(token);
  if(decoded) { 
      cookies.set('token');
      res.writeHead(302, {
        'Location': '/'
      });
      res.end();
      return;
    }
   else {
    cookies.set('token');
    authFail(res, done);
    return;
  }
})


// create JWT
function generateToken(opts, user) {
    opts = opts || {};

    // By default, expire the token after 7 days.
    // NOTE: the value for 'exp' needs to be in seconds since
    // the epoch as per the spec!
    var expiresDefault = '7d';

    var token = jwt.sign({
        name: user['name'],
        role: user['role']
    }, secret, {
        expiresIn: opts.expires || expiresDefault
    });

    return token;
}

function authSuccess(req, res, user) {
    var token = generateToken(null, user);

    res.cookie('token', token)
    res.writeHead(302, {
        'Location': '/bar'
    });
    return res.end();
}

function authFail(res, callback) {
    return res.render('fail');
}

function hash(password) {
    return execSync("./bhash.py " + password + " " + seed).toString().slice(0, -1)
}

function verify(token) {
    var decoded = false;
    jwt.verify(token, secret, function(err, payload) {
        if (err) {
            decoded = false; // still false
        } else {
            decoded = payload;
        }
    });
    return decoded;
}