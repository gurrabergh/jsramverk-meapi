const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require('morgan');
const cors = require('cors');
var bcrypt = require('bcryptjs');

const db = require("./db/database.js");
const port = 1337;

const mongo = require("mongodb").MongoClient;
const dsn = "mongodb://localhost:27017/messages";

require('dotenv').config();
app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

if (process.env.NODE_ENV !== 'test') {
    // use morgan to log at command line
    app.use(morgan('combined')); // 'combined' outputs the Apache style LOGs
}



// Add a route
app.get("/", (req, res) => {
    let sql = "SELECT heading, content FROM texts WHERE id = 1";

    db.get(sql, (err, row) => {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
        if (row) {
            return res.status(201).json({
                data: {
                    text: row
                }
            });
        }
        return res.status(403).json({
            data: {
                msg: 'text failed'
            }
        });
    });
});

app.get("/reports/week/:id", (req, res) => {
    let id = parseInt(req.params.id) + 1;
    let sql = "SELECT heading, content FROM texts WHERE id = ?";

    db.get(sql, [id], (err, row) => {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
        if (row) {
            return res.status(201).json({
                data: {
                    text: row
                }
            });
        }
        return res.status(403).json({
            data: {
                msg: 'text failed'
            }
        });
    });
});

app.get("/admin", (req, res) => {
    let sql = "SELECT * FROM texts";

    db.all(sql, (err, row) => {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
        if (row) {
            return res.status(201).json({
                data: {
                    text: row
                }
            });
        }
        return res.status(403).json({
            data: {
                msg: 'text failed'
            }
        });
    });
});

app.get("/admin/edit/:id", (req, res) => {
    let sql = "SELECT id, heading, content FROM texts WHERE id = ?";

    db.get(sql, [req.params.id], (err, row) => {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
        if (row) {
            return res.status(201).json({
                data: {
                    text: row
                }
            });
        }
        return res.status(403).json({
            data: {
                msg: 'text failed'
            }
        });
    });
});

app.post("/register", (req, res) => {
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(req.body.psw, salt, function(err, hash) {
            db.run("INSERT INTO users (email, password) VALUES (?, ?)",
                req.body.usr,
                hash, (err) => {
                    if (err) {
                        return res.status(403).json({
                            data: {
                                msg: 'failed'
                            }
                        });
                    }
                    return res.status(201).json({
                        data: {
                            msg: 'success'
                        }
                    });
                });
        });
    });
});

app.post("/login", (req, res) => {
    checkLogin(req, res);
});

app.post("/reports",
    (req, res, next) => checkToken(req, res, next),
    (req, res) => addReport(res, req.body));

app.post("/edit",
    (req, res, next) => checkToken(req, res, next),
    (req, res) => editReport(res, req.body));

app.post("/delete",
    (req, res, next) => checkToken(req, res, next),
    (req, res) => deleteReport(res, req.body));

app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }

    res.status(err.status || 500).json({
        "errors": [
            {
                "status": err.status,
                "title":  err.message,
                "detail": err.message
            }
        ]
    });
    return undefined;
});

function checkLogin(req, res) {
    let sql = "SELECT password FROM users WHERE email = ?";

    db.get(sql, [req.body.usr], (err, row) => {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'login failed'
                }
            });
        }
        if (row) {
            bcrypt.compare(req.body.psw, row.password, function(err, result) {
                if (result === true) {
                    const jwt = require('jsonwebtoken');
                    const payload = { email: req.body.usr };
                    const secret = process.env.JWT_SECRET;
                    const token = jwt.sign(payload, secret, { expiresIn: '1h'});

                    return res.status(201).json({
                        data: {
                            token: token
                        }
                    });
                }
                return res.status(403).json({
                    data: {
                        msg: 'login failed'
                    }
                });
            });
            return undefined;
        }
        return res.status(403).json({
            data: {
                msg: 'login failed'
            }
        });
    });
    return undefined;
}

function checkToken(req, res, next) {
    const jwt = require('jsonwebtoken');
    const token = req.headers['x-access-token'];

    jwt.verify(token, process.env.JWT_SECRET, function(err) {
        if (err) {
            return res.status(403).json({
                data: {
                    msg: 'not authorized jwt',
                    jwt: err
                }
            });
        }
        next();
        return undefined;
    });
}

function addReport(res, body) {
    db.run(`INSERT INTO texts (heading, content) VALUES(?,?)`,
        [body.heading, body.content], function(err) {
            if (err) {
                return res.status(201).json({
                    data: {
                        msg: 'not authorized add'
                    }
                });
            }
            return res.status(201).json({
                data: {
                    msg: 'success'
                }
            });
        });
}

function editReport(res, body) {
    db.run(`UPDATE texts SET heading = ?, content = ? WHERE id = ?`,
        [body.heading, body.content, body.id], function(err) {
            if (err) {
                return res.status(401).json({
                    data: {
                        msg: 'not authorized'
                    }
                });
            }
            return res.status(201).json({
                data: {
                    msg: 'success'
                }
            });
        });
}

function deleteReport(res, body) {
    db.run(`DELETE FROM texts WHERE id = ?`, [body.id], function(err) {
        if (err) {
            return res.status(401).json({
                data: {
                    msg: 'not authorized'
                }
            });
        }
        return res.status(201).json({
            data: {
                msg: 'success'
            }
        });
    });
}

app.get("/chat", async (request, response) => {
    try {
        let res = await getOldMessages(dsn, "messages", {}, {}, 0);

        console.log(res);
        response.json(res);
    } catch (err) {
        console.log(err);
        response.json(err);
    }
});

app.post("/chat", async (req, response) => {
    try {
        let res = await saveMessage(req.body);

        response.json(res);
    } catch (err) {
        console.log(err);
        response.json(err);
    }
});

async function getOldMessages(dsn, colName, criteria, projection, limit) {
    const client  = await mongo.connect(dsn);
    const db = await client.db();
    const col = await db.collection(colName);
    const res = await col.find(criteria, projection).limit(limit).toArray();

    await client.close();

    return res;
}

async function saveMessage(message) {
    mongo.connect(dsn, function(err, db) {
        if (err) {
            throw err;
        }
        var dbo = db.db("messages");
        var msg = { text: message };

        dbo.collection("messages").insertOne(msg, function(err, res) {
            if (err) {
                throw err;
            }
            console.log(res);
            db.close();
        });
    });
}


// Start up server
const server = app.listen(port);
const io = require('socket.io')(server);

io.origins(['https://me.gustavbergh.me:443']);

io.on('connection', function (socket) {
    socket.on('chat message', function (message) {
        console.log('message' + message);
        saveMessage(message);
        io.emit('chat message', message);
    });
});

module.exports = server;
