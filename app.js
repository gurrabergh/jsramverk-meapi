const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require('morgan');
const cors = require('cors');
var bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./db/texts.sqlite');

const port = 1337;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

app.use((req, res, next) => {
    console.log(req.method);
    console.log(req.path);
    next();
});

if (process.env.NODE_ENV !== 'test') {
    // use morgan to log at command line
    app.use(morgan('combined')); // 'combined' outputs the Apache style LOGs
}



// Add a route
app.get("/", (req, res) => {
    let sql = "SELECT heading, content FROM texts WHERE id = 1";
    db.get(sql, (err, row) => {
        if (err) {
            return res.status(201).json({
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
        } else {
            return res.status(201).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
    });
});

app.get("/reports/week/1", (req, res) => {
    let sql = "SELECT heading, content FROM texts WHERE id = 2";
    db.get(sql, (err, row) => {
        if (err) {
            return res.status(201).json({
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
        } else {
            return res.status(201).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
    });
});

app.get("/reports/week/2", (req, res) => {
    let sql = "SELECT heading, content FROM texts WHERE id = 3";
    db.get(sql, (err, row) => {
        if (err) {
            return res.status(201).json({
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
        } else {
            return res.status(201).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
    });
});

app.get("/admin", (req, res) => {
    let sql = "SELECT * FROM texts";
    db.all(sql, (err, row) => {
        if (err) {
            return res.status(201).json({
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
        } else {
            return res.status(201).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
    });
});

app.get("/admin/edit/:id", (req, res) => {

    let sql = "SELECT id, heading, content FROM texts WHERE id = ?";
    db.get(sql, [req.params.id], (err, row) => {
        if (err) {
            return res.status(201).json({
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
        } else {
            return res.status(201).json({
                data: {
                    msg: 'text failed'
                }
            });
        }
    });
});

app.post("/register", (req, res) => {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    var msg = '';
    console.log(req.body)
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(req.body.psw, salt, function(err, hash) {
            db.run("INSERT INTO users (email, password) VALUES (?, ?)",
            req.body.usr,
            hash, (err) => {
                if (err) {
                    return res.status(201).json({
                        data: {
                            msg: 'failed'
                        }
                    });
                }
                res.status(201).json({
                    data: {
                        msg: 'success'
                    }
                });
            });
        });
    });

});

app.post("/login", (req, res, next) => {
    checkLogin(req, res)
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
});

function checkLogin(req, res) {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    var msg = '';
    console.log(req.body)
    let sql = "SELECT password FROM users WHERE email = ?";
        db.get(sql, [req.body.usr], (err, row) => {
            if (err) {
                return res.status(201).json({
                    data: {
                        msg: 'login failed'
                    }
                });
            }
            if (row) {
                bcrypt.compare(req.body.psw, row.password, function(err, result) {
                    console.log(result)
                    if (result == true) {
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
                });
            } else {
                return res.status(201).json({
                    data: {
                        msg: 'login failed'
                    }
                });
            }
        });
}

function checkToken(req, res, next) {
    const jwt = require('jsonwebtoken');
    const token = req.headers['x-access-token'];
    jwt.verify(token, process.env.JWT_SECRET, function(err, decoded) {
        if (err) {
            console.log('fail')
            return res.status(201).json({
                data: {
                    msg: 'not authorized'
                }
            });
        }
        next();
    });
}

function addReport(res, body) {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    db.run(`INSERT INTO texts (heading, content) VALUES(?,?)`, [body.heading, body.content], function(err) {
        if (err) {
            console.log(err.message);
            return res.status(201).json({
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

function editReport(res, body) {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    db.run(`UPDATE texts SET heading = ?, content = ? WHERE id = ?`, [body.heading, body.content, body.id], function(err) {
        if (err) {
            console.log(err.message);
            return res.status(201).json({
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
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    db.run(`DELETE FROM texts WHERE id = ?`, [body.id], function(err) {
        if (err) {
            console.log(err.message);
            return res.status(201).json({
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

// Start up server
app.listen(port, () => console.log(`Example API listening on port ${port}!`));
