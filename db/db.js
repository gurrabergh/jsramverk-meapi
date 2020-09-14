async function regUser(usr, psw) {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    var msg = '';
    db.run("INSERT INTO users (email, password) VALUES (?, ?)",
    req.body.usr,
    req.body.psw, (err) => {
        if (err) {
            msg = 'failed'
            return msg
        }

        return msg = 'success'
    }
}

module.exports = {
    'regUser': regUser
}