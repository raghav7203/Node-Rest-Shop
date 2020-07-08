const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // read their documentation for better understanding of their methods


const User = require('../models/user');

exports.user_signup = (req, res, next) => {
    User.find({email: req.body.email})
    .exec()
    .then(user => {
        if(user.length >= 1){ // user is array not simply null, length will be >=1 if same mail exists else will be empty array
            return res.status(409).json({
                message: 'This email is already taken'
            });
        }
        else{
            bcrypt.hash(req.body.password, 10, (err, hash) => {
                if(err){
                    return res.status(500).json({
                        error: err
                    });
                }
                else{
                    const user = new User({
                        _id: new mongoose.Types.ObjectId(),
                        email: req.body.email,
                        password: hash
                    });
                    user
                    .save()
                    .then(result => {
                        console.log(result);
                        res.status(201).json({
                            message: 'User created'
                        });
                    })
                    .catch(err => {
                        console.log(err);
                        res.status(500).json({
                            error: err
                        })
                    });
                }
            });
        }
    })
}

exports.user_login = (req, res, next) => {
    User.find({ email: req.body.email})
    .exec()
    .then(user => { // user is an array here, coz thats what we got as a result of find
        if(user.length < 1){
            return res.status(401).json({
                message: 'Auth failed'
            });
        }
        // checking password to the password of user[0] i.e the one user we have got
        bcrypt.compare(req.body.password, user[0].password, (err, result) => {
            if(err){
                return res.status(401).json({
                    message: 'Auth failed'
                }); 
            }
            if(result){
               const token = jwt.sign(
                  {
                    email: user[0].email,
                    userId: user[0]._id
                  },
                  process.env.JWT_KEY,
                  {
                    expiresIn: "1h"
                  }
                );
                return res.status(200).json({
                    message: 'Auth successful',
                    token: token
                });
            }
            return res.status(401).json({
                message: 'Auth failed'
            }); // if password is incorrect
        })
    })
    .catch(err => {
        console.log(err);
        res.status(500).json({
          error: err
        });
      });
}

exports.user_delete = (req, res, next) => {
    User.remove({_id: req.params.userId})
    .exec()
    .then(result => {
        res.status(200).json({
            message: 'user deleted'
        });
    })
    .catch(err => {
        console.log(err);
        res.status(500).json({
          error: err
        });
      })
}