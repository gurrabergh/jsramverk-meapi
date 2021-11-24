const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require('morgan');
const cors = require('cors');

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


app.get("/chat", async (request, response) => {
    try {
        let res = await getOldMessages(dsn, "messages", {}, {}, 0);

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
            db.close();
        });
    });
}


// Start up server
const server = app.listen(port);
const io = require('socket.io')(server);


io.on('connection', function (socket) {
    socket.on('chat message', function (message) {
        console.log('message' + message);
        saveMessage(message);
        io.emit('chat message', message);
    });
});

module.exports = server;
