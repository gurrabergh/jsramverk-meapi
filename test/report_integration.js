process.env.NODE_ENV = 'test';

const chai = require('chai');
const chaiHttp = require('chai-http');
const server = require('../app.js');

chai.should();

chai.use(chaiHttp);

describe('Reports', () => {
    var tests = [
        "/reports/week/1",
        "/reports/week/2",
        "/reports/week/3",
        "/"
    ];

    tests.forEach(function(test) {
        describe('GET' + test, () => {
            it('200 HAPPY PATH', (done) => {
                chai.request(server)
                    .get(test)
                    .end((err, res) => {
                        res.should.have.status(201);
                        res.body.data.should.be.an("object");
                        res.body.data.text.should.be.an("object");
                        res.body.data.text.heading.length.should.be.above(0);
                        res.body.data.text.content.length.should.be.above(0);
                        done();
                    });
            });
        });
    });

    it('200 HAPPY PATH', (done) => {
        chai.request(server)
            .get('/admin')
            .end((err, res) => {
                res.should.have.status(201);
                res.should.be.an("object");
                res.text.length.should.be.above(0);
                done();
            });
    });
});

describe('Register', () => {
    describe('POST /register', () => {
        it('Test to register with new user', (done) => {
            chai.request(server)
                .post("/register")
                .send({ usr: 'test', psw: 'test'})
                .end((err, res) => {
                    res.should.have.status(201);
                    res.body.should.be.an("object");
                    res.body.data.should.be.an("object");
                    // res.body.data.length.should.be.above(0);

                    done();
                });
        });
    });

    describe('POST /register', () => {
        it('Test to register with existing user', (done) => {
            chai.request(server)
                .post("/register")
                .send({ usr: 'test', psw: 'test'})
                .end((err, res) => {
                    res.should.have.status(403);
                    res.body.should.be.an("object");
                    res.body.data.should.be.an("object");
                    // res.body.data.length.should.be.above(0);

                    done();
                });
        });
    });
});

describe('Login', () => {
    describe('POST /login', () => {
        it('Test to login with valid user', (done) => {
            chai.request(server)
                .post("/login")
                .send({ usr: 'test', psw: 'test'})
                .end((err, res) => {
                    res.should.have.status(201);
                    res.body.should.be.an("object");

                    done();
                });
        });
    });
});

describe('Login', () => {
    describe('POST /login', () => {
        it('Test to login with invalid user', (done) => {
            chai.request(server)
                .post("/login")
                .send({ usr: 'test1', psw: 'test'})
                .end((err, res) => {
                    res.should.have.status(403);
                    res.body.should.be.an("object");

                    done();
                });
        });
    });
});

describe('Edit Reports', () => {
    var tests = [
        "/reports",
        "/edit",
        "/delete",
    ];

    tests.forEach(function(test) {
        describe('POST' + test, () => {
            it('Testing post routes', (done) => {
                chai.request(server)
                    .post(test)
                    .end((err, res) => {
                        res.should.have.status(403);
                        res.body.data.should.be.an("object");
                        done();
                    });
            });
        });
    });
});

describe('Edit Reports', () => {
    var tests = [
        "/reports",
        "/edit",
        "/delete",
    ];

    tests.forEach(function(test) {
        let token = process.env.JWT_TOKEN;

        describe('POST' + test, () => {
            it('Testing post routes', (done) => {
                chai.request(server)
                    .post(test)
                    .set('x-access-token', token)
                    .end((err, res) => {
                        res.should.have.status(201);
                        res.body.data.should.be.an("object");
                        done();
                    });
            });
        });
    });
});
