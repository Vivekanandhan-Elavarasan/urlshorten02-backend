var express = require('express');
const bodyParser = require('body-parser');
var cors = require('cors');
const fs = require('fs');
const jwt = require("jsonwebtoken");
const url = require('url');

var app = express();

app.use(cors());

const MongoClient = require('mongodb').MongoClient;

var randomstring = require("randomstring");

const uri = `mongodb+srv://vivekuser:vivekadmin@cluster0-mfrcr.mongodb.net/shorturl02?retryWrites=true&w=majority`;

app.use(bodyParser.json());

const bcrypt = require('bcrypt');

require('dotenv').config();

const jwtKey = "vjgcgcgcgjcxcohinnkfyxx";


var nodemailer = require('nodemailer');
const { query } = require('express');
const { JsonWebTokenError } = require('jsonwebtoken');

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASS
    }
});


var server = app.listen(process.env.PORT || 3000, function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log("Example app listening at http://%s:%s", host, port)
})



app.get('/', function (req, res) {
    res.status(200).send(' /register ,   /login , /reset (reset password)');
})


app.post("/register", function (req, res) {
    var email = req.body.email;
    var pass = req.body.pass;

    console.log(req.body);

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                console.log("Present");
                res.status(400).send("Email already Registered !");
            }
            else {
                console.log("Not Present");
                bcrypt.hash(pass, 10, function (err, hash) {
                    let secretString = randomstring.generate(4);
                    let verifyString = randomstring.generate(4);
                    var testObj = { email: email, pass: hash, secretString: secretString, verifyString: verifyString, verified: false, role: "User" };
                    console.log(testObj);
                    dbObject.collection("userCollTwo").insertOne(testObj, function (err, resp) {
                        if (err) throw err;
                        res.end("Email Registered ! Check inbox for verification link !");
                        sendVerifyMail(email);
                        db.close();
                    });
                });
            }
        })
    });
});


app.post("/login", function (req, res) {
    var email = req.body.email;
    var pass = req.body.pass;

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        var testObj = { email: email, pass: pass };

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                console.log(data[0]);
                if (data[0].verified === false) {
                    res.status(200).json({message : "Please verify email !"});
                }
                else {
                    bcrypt.compare(pass, data[0].pass, function (err, result) {
                        console.log(result);
                        if (result) {
                            let token = jwt.sign({ email: data[0].email, role: "User" }, jwtKey, { expiresIn: 86400 });
                            res.status(200).json({ message: "Valid login", token: token });
                        } else {
                            res.status(200).json({message : "Invalid credentials !"});
                        }
                    });
                }
            }
            else {
                console.log("Not Present");
                res.status(200).json({message : "Email not registered !"});
            }
        });
        db.close();
    });
});

app.post("/resendVerificationMail", function (req, res) {
    let email = req.body.email;
    sendVerifyMail(email);
    res.status(200).end("Verification email send again !");
});

app.get("/dashboard", [tokenAuthorization], function (req, res) {

    var authToken = req.headers.authorization;

    var value = jwt.verify(authToken, jwtKey);

    var email = value['email'];

    const client = new MongoClient(uri, { useNewUrlParser: true });

    var output = [];

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        dbObject.collection("urlCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            console.log(data);
            for (let i = 0; i < data.length; i++) {
                output.push(data[i]);
            }
            return res.status(200).json(output);
        });
    });
});

function tokenAuthorization(req, res, next) {
    let authToken = req.headers.authorization;

    if (authToken === undefined) {
        return res.status(401).json({ message: "Unauthorized User" });
    }
    else {
        jwt.verify(authToken, jwtKey, (err, value) => {
            if (err) {
                return res.status(401).json({ message: "Unauthorized Access" });
            }
            else {
                console.log(value);
                next();
            }
        });
    }
}

function getEmailFromToken(req) {
    let authToken = req.headers.authorization;

    if (authToken === undefined) {
        return null;
    }
    else {
        jwt.verify(authToken, jwtKey, (err, value) => {
            if (err) {
                return null;
            }
            else {
                console.log(value);
                return value['email'];
            }
        });
    }
}


app.get("/verify", function (req, res) {

    const queryObject = url.parse(req.url, true).query;

    var email = queryObject['email'];
    var verifyString = queryObject['verifyString'];

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        var testObj = { email: email };

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                if (data[0].verified === true) {
                    res.end("Account already verified !");
                }
                else {
                    if (data[0].verifyString === verifyString) {

                        var newvalues = { $set: { email: data[0].email, pass: data[0].pass, secretString: data[0].secretString, verifyString: data[0].verifyString, verified: true, role: "User" } };

                        dbObject.collection("userCollTwo").updateOne({ email: email }, newvalues, function (dberr, dbdata) {
                            if (dberr) throw dberr;
                            res.status(200).send("Account verified");
                        });
                    }
                    else {
                        res.end("Invalid verification link");
                    }
                }
            }
            else {
                res.end("Invalid verification link");
            }
            db.close();
        });
    });
});


app.post("/shorten", [tokenAuthorization], function (req, res) {

    var url = req.body.url;

    let authToken = req.headers.authorization;

    if (authToken === undefined) {
        res.status(401).end("Unauthorized");
    }
    else {

        var value = jwt.verify(authToken, jwtKey);

        var email = value['email'];

        var shortURL = randomstring.generate(4);

        const client = new MongoClient(uri, { useNewUrlParser: true });

        client.connect(function (dbError, db) {
            if (dbError) throw dbError;

            var dbObject = db.db("testDbSix");

            var dbRecord = { shortURL: shortURL, longURL: url, email: email, count: 0 };

            console.log(dbRecord);

            dbObject.collection("urlCollTwo").find({ shortURL: shortURL }).toArray(function (error, data) {
                if (error) throw error;
                if (data.length === 0) {

                    dbObject.collection("urlCollTwo").insertOne(dbRecord, function (error2, data) {
                        if (error2) throw error2;
                        res.status(200).json({ message: "URL Successfully shortened", link: process.env.SERVER + shortURL });
                        db.close();
                    });

                }
                else {
                    res.status(401).json({ message: "Please Try Again" });
                }
            });

        });
    }
});


app.get("/:shortURL", function (req, res) {
    const client = new MongoClient(uri, { useNewUrlParser: true });

    var shortURL = req.params.shortURL;


    client.connect(function (err, db) {
        var dbRecord = { shortURL: shortURL };

        var dbObject = db.db("testDbSix");

        var longURL = "";

        console.log(shortURL);

        dbObject.collection("urlCollTwo").find(dbRecord).toArray(function (error, data) {
            if (error) throw error;
            if (data.length === 0) {
                return res.status(404).end("Invalid URL");
            }
            else {
                dbObject.collection("urlCollTwo").updateOne(dbRecord, { $inc: { count: 1 } }, function (dberr, dbdata) {
                    if (dberr) throw dberr;
                    db.close();
                    console.log(data[0].longURL);
                    if (data[0].longURL.includes("https://")) {
                        return res.status(301).redirect(data[0].longURL);
                    }
                    else {
                        return res.status(301).redirect("https://" + data[0].longURL);
                    }
                });
            }
        });

    });
});



function sendVerifyMail(email) {

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        var testObj = { email: email };

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                console.log(email + " : " + data[0].verifyString);
                let htmlString = `<a href="${process.env.SERVER}verify?email=${email}&verifyString=${data[0].verifyString}">Click here to verify account !</a>`;
                console.log(htmlString);
                var mailOptions = {
                    from: 've49215@gmail.com',
                    to: email,
                    subject: 'URL Shortener Verification Mail',
                    text: "Click here to verify account !",
                    html: htmlString
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                        //res.status(500).send("error");
                    } else {
                        console.log('Verification Email sent: ' + info.response);
                        //res.status(200).send('Verification Email sent: ' + info.response);
                    }
                });
            }
            else {
                console.log("Not Present");
                //res.status(400).send("Email not registered !");
            }
        })
    });
}

app.post("/resetStepOne", function (req, res) {
    var email = req.body.email;

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        var testObj = { email: email };

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                var mailOptions = {
                    from: 've49215@gmail.com',
                    to: email,
                    subject: 'URL Shortener password reset',
                    text: 'The secret is ' + data[0].secretString
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                        res.status(500).send("Error ! Please try again !");
                    } else {
                        console.log('Email sent: ' + info.response);
                        res.status(200).send('Email sent. Check Inbox');
                    }
                });
            }
            else {
                console.log("Not Present");
                res.status(400).send("Email not registered !");
            }
        })
    });
});

app.post("/resetStepTwo", function (req, res) {
    let secret = req.body.secret;
    let email = req.body.email;
    let newPass = req.body.newPass;

    const client = new MongoClient(uri, { useNewUrlParser: true });

    client.connect(function (err, db) {
        if (err) throw err;

        var dbObject = db.db("testDbSix");

        dbObject.collection("userCollTwo").find({ email: email }).toArray(function (err, data) {
            if (err) throw err;
            if (data.length > 0) {
                if (data[0].secretString === secret) {
                    let secretString = randomstring.generate(4);
                    bcrypt.hash(newPass, 10, function (error, hash) {
                        var newvalues = { $set: { email: email, pass: hash, secretString: secretString } };

                        dbObject.collection("userCollTwo").updateOne({ email: email }, newvalues, function (dberr, dbdata) {
                            if (dberr) throw dberr;
                            res.status(200).send("Password updated");
                            db.close();
                        });
                    });
                }
                else {
                    res.status(400).send("Invalid secret");
                }
            }
            else {
                console.log("Not Present");
                res.status(400).send("Email not registered !");
            }
        })
    });
});