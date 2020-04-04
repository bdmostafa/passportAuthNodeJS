const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User model
const User = require('../models/User');

// Login Page
router.get('/login', (req, res) => res.render('login'));

// Registraion Page
router.get('/register', (req, res) => res.render('register'));

// Register Handle
router.post('/register', (req, res) => {
    // console.log(req.body);
    // res.send('hello');

    const { name, email, password, password2 } = req.body;
    let errors = [];
    
    // Check required fields
    if(!name || !email || !password || !password2) {
        errors.push ({ msg: 'Please fill in all fields' });
    }

    // Password matching check
    if(password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    // Check password length
    if(password.length < 4) {
        errors.push({ msg: 'Password must be at least 4 chars' });
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // res.send('Passed');

        // Validation passing
        User.findOne({ email: email })
            .then(user => {
                if(user) {
                    // Check User exists
                    errors.push({ msg: 'Email is already registered' });
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    const newUSer = new User({
                        name,
                        email,
                        password
                    });
                    // console.log(newUSer);
                    // res.send('hello new user');

                    // Technique 1 (generate a salt and hash on separate function calls)
                    bcrypt.genSalt(10, (err, salt) =>
                        bcrypt.hash(newUSer.password, salt, (err, hash) => {
                            if(err) throw err;
                            // Set password to hashed
                            newUSer.password = hash;
                            // Save user
                            newUSer.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered successfully and can log in');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                    }));

                    // Technique 2 (auto-gen a salt and hash) 
                    // bcrypt.hash(newUSer.password, 10, (err, hash) => {
                    //     if(err) throw err;
                    //     // Set password to hashed
                    //     newUSer.password = hash;
                    //     // Save user
                    //     newUSer.save()
                    //         .then(user => {
                    //             res.redirect('/login');
                    //         })
                    //         .catch(err => console.log(err));
                    // });
                }
            });
    }
});

// Handle Login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// Handle Logout
router.get('/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', 'You are now logged out.');
    res.redirect('/users/login');
})

module.exports = router;
