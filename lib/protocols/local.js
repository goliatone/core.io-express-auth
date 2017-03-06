/*jshint esversion:6, node:true*/
'use strict';
/*
 * Local Authentication Protocol
 *
 * Use username/email and password to auth a user.
 * The module also provides functions to register
 * new users, assign passwords to registered suers,
 * and validating login.
 */
module.exports = function(passport, config){
    let Local = {};

    let Passport = config.passport.getPassport();
    let PassportUser = config.passport.getPassportUser();

    Local.register = function(req, res, next){
        Local.createUser(req, res, next);
    };

    Local.createUser = function(req, res, next){
        //TODO: extract only the attributes we want :)
        let _user = req.body;

        let accessToken = generateToken();
        let password = _user.password;

        delete _user.password;

        return PassportUser.create(_user).then((user)=>{
            return Passport.create({
                user: user.id,
                protocol: 'local',
                password: password,
                accessToken: accessToken
            }).then(()=> {
                next(null, user);
                return user;
            }).catch((err)=>{
                if(err.code === 'E_VALIDATION'){
                    // err = new SAError({originalError: err});
                }
                return PassportUser.destroy(user).then(()=>{
                    next(err);
                }).catch(next);
            });
        }).catch((err)=>{
            config.logger.error(err);

            // if(err.code === 'E_VALIDATION'){
            //     return next(new SAError({originalError: err}));
            // }
            next(err);
        });
    };

    Local.updateUser = function(_user, next){
        //TODO: use local strategy config options:
        //usernameField = 'username'
        //passwordField = 'password'
        let password = _user.password;
        delete _user.password;

        let query = {};

        //TODO: Have an option in config to get the query
        if(_user.id) query.id = _user.id;
        else if(_user.username) query.username = _user.username;
        else if(_user.email) query.email = _user.email;
        else {
            return next(new Error('Invalid query'));
        }

        return PassportUser.update(query, _user).then((user)=>{
            if(!user){
                return next(new Error('Error creating user'));
            }
            if(Array.isArray(user)) user = user[0];

            if(!!password){
                Passport.findOne({
                    protocol: 'local',
                    user: user.id
                }).then((passport)=>{
                    passport.password = password;
                    passport.save((err)=>{
                        if(err){
                            config.logger.error(err);

                            // if(err.code === 'E_VALIDATION'){
                            //     return next(new SAError({originalError: err}));
                            // }
                            return next(err);
                        }
                        next(null, user);
                    });
                }).catch(next);
            } else {
                next(null, user);
            }
        }).catch((err)=>{
            config.logger.error(err);

            // if(err.code === 'E_VALIDATION'){
            //     return next(new SAError({originalError: err}));
            // }
            next(err);
        });
    };

    /*
     * This function can be used to assign a
     * local Passport to a user who doens't
     * have one already.
     * This would be the case if the user
     * registered using a third-party service
     * and therefore never set a password.
     */
    Local.connect = function(req, res, next){
        let user = req.user,
            password = req.param('password');

        Passport.findOne({
            protocol: 'local',
            user: user.id
        }).then((passport)=>{
            if(!passport){
                return Passport.create({
                    protocol: 'local',
                    password: password,
                    user: user.id
                }).exec(next);
            }
            next(null, passport);
        }).catch(next);
    };

    /**
     * Login method.
     * @method login
     * @param  {Object}   req        Express request
     * @param  {String}   identifier Username|email
     * @param  {String}   password
     * @param  {Function} next
     * @return {void}
     */
    Local.login = function(req, identifier, password, next){
        let isEmail = validateEmail(identifier);
        let query = isEmail ? {email: identifier} : {username: identifier};

        PassportUser.findOne(query).then((user)=>{
            if(!user){
                //TODO: Better messages...
                let message;
                if(isEmail){
                    message = 'Email not found'
                    req.res.flash('error', 'Error.Passport.Email.NotFound');
                } else {
                    message = 'Username not found'
                    req.res.flash('error', 'Error.Passport.Username.NotFound');
                }
                return next(null, false, message, 401);
            }

            return Passport.findOne({
                protocol: 'local',
                user: user.id
            }).then((passport)=>{
                if(passport){
                    return passport.validatePassword(password).then((res)=>{
                        if(!res){
                            req.res.flash('error', 'Error.Passport.Password.Wrong');
                            return next(null, false);
                        }
                        return next(null, user, passport);
                    }).catch(next);
                }
                req.res.flash('error', 'Error.Passport.Password.NotSet');
                return next(null, false, 'Password not set', 401);
            }).catch(next);
        }).catch(next);
    };

    Local.update = function(user, next){
        Local.updateUser(user, next);
    };

    return Local;
};

function generateToken(){
    const crypto = require('crypto');
    const base64url = require('base64url');
    // return crypto.randomBytes(48).toString('hex');
    return base64url(crypto.randomBytes(48));
}

function validateEmail(str){
    const EMAIL_REGEX = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i;
    return EMAIL_REGEX.test(str);
}
