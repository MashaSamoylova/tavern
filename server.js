var jwt = require('jsonwebtoken');
var express = require("express");
var cookieParser = require('cookie-parser')
const http = require('http')
const WebSocket = require('ws')

var MongoClient = require("mongodb").MongoClient

var mongoClient = new MongoClient("mongodb://database:27017/", {
    useNewUrlParser: true
});

// Roles
const adminRole = 'Admin'
const userRole = 'User'

// Port
var port = 8080;

//JWT secret
var secret = process.env.JWT_SECRET || "CHANGE_THIS_TO_SOMETHING_RANDOM";

var app = express();
var router = express.Router();

app.set("view engine", "ejs");
app.use(express.static(__dirname + '/views'));
app.use(cookieParser());
app.use(express.urlencoded());
app.use('/', router);

server = http.createServer(app);

const wss = new WebSocket.Server({ server })

wss.on('connection', function connection (ws, req) {
  ws.on('message', function incoming (message) {

    console.log('received: %s', message)
    mongoClient.connect(function(err, client) {
                if (err) {
                    return console.log(err);
                }

                let owner = {
                    name: message
                }

                console.log("owner ", owner);

                client.db("BAR").collection("recipes").find(owner).toArray(function(err, results) {
                    results.forEach(function (res) {
                        ws.send(res.recipe)
                    })
                });
            });
  })

  ws.send('something')
})

//app.listen(port);
server.listen(port);


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
            password: req.body.password,
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
                req.body.password && req.body.password === u.password) {
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
    console.log(decoded);
    if (!decoded) {
        return authFail(res);
    } else {
        if (decoded.role === adminRole) {
            mongoClient.connect(function(err, client) {
                if (err) {
                    return console.log(err);
                }

                client.db("BAR").collection("recipes").find().toArray(function(err, results) {
                    console.log("results:", results);
                    console.log("render");
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

                console.log("owner ", owner);

                client.db("BAR").collection("recipes").find(owner).toArray(function(err, results) {
                    console.log("results:", results);
                    console.log("render");
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

        console.log("new recipe", newRecipe)

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
    mongoClient.connect(function(err, client) {
        if (err) {
            return console.log(err);
        }

        client.db("BAR").collection("users").find().toArray(function(err, results) {
            console.log("results:", results);
            console.log("render");
            return res.render('bar', {
                records: results
            });
        });
    });
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
    console.log("auth succsess")

    res.cookie('token', token)
    res.writeHead(302, {
        'Location': '/bar'
    });
    return res.end();
}

function authFail(res, callback) {
    return res.render('fail');
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