const toolbox = require("../self_modules/toolbox");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const data = require("../data.json");
const _ = require("lodash")
let blogMessages = [];
const path = require('path');

//logging system ,content in error.log file
const winston = require('winston');
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.json()
    ),
    defaultMeta: { service: 'login-service' },
    transports: [
      new winston.transports.File({ filename: path.join(__dirname, 'error.log'), level: 'error' }),
     
    ],
});

//hash method
function badHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash += str.charCodeAt(i);
    }
    return hash % 10; //will an output from 0-9 ,10 % collision rate
}

exports.connectUser = (req, res) => {
    let body = req.body
    let user = null
    if (!toolbox.checkMail(body.mail)) {
        logger.error('The mail doesn\'t use a correct format', {
            ip: req.ip,
            url: req.originalUrl,
            body: _.omit(req.body, ['password']), // omit the password for security reasons
        });
        res.status(400).send('The mail doesn\'t use a correct format');
    } else {
        data.forEach(el => {
            if(el.mail === body.mail) {
                user = el
            }
        });
        if(user == null){
            logger.error('This user does not exist', {
                ip: req.ip,
                url: req.originalUrl,
                body: _.omit(req.body, ['password']), // omit the password for security reasons
            });
            res.status(404).send('This user does not exist');
        } else {
            if (badHash(body.password) == user.password) {
                const token = jwt.sign({ user_id: user.id, user_role: user.role }, process.env.ACCESS_TOKEN_SECRET);
                res.status(200).json({ token, role: user.role })
            } else {
                logger.error('Invalid authentication', {
                    ip: req.ip,
                    url: req.originalUrl,
                    body: _.omit(req.body, ['password']), // omit the password for security reasons
                });
                res.status(403).send('Invalid authentication')
            }
        }
    }
};

exports.fetchDataUser = (req, res) => {
    let usr = null
    data.forEach(el => {
        if(el.id === req.body.user_id){
            usr = _.cloneDeep(el)
        }
    });
    if(usr == null) {
        res.status(500).send('Wrong cookies data. Please contact the webmaster')
    } else {
        delete usr.password
        res.status(200).json(usr);
    }
}

exports.getVictory = (req, res) => {
    let usr;
    let usrList = [];
    data.forEach(el => {
        usr = _.cloneDeep(el)
        delete usr.password
        usrList.push(usr)
    });
    res.status(200).json(usrList);
}

exports.fetchBlogMessages = (req, res) => {
    res.status(200).json(blogMessages);
}

exports.createBlogmessage = (req, res) => {
    let body = req.body
    if(body.message === null || body.message === "") {
        res.status(400).send('Cannot add an empty message');
    } else {
        blogMessages.push(body.message)
        res.status(200).send("Message Added");
    }
}