'use strict';

//TODO: pull this from where it is
const localProtocol = require('./local');

/**
 * Middleware to register basic auth.
 * If the HTTP Basic Auth header contains
 * credentials, the authentication happens
 * for the user in a single request.
 * 
 * @param {Express} app Express app
 * @param {Object} config Configuration object
 */
module.exports = function(app, config) {

    return function $basic(req, res, next) {
        const passport = req._passport.instance;
        const handler = passport.authenticate('basic', {
            session: false,
            /*
             * We want to bubble up errors,
             * this makes passport to fail with
             * next(new AuthoriaztionError(mesage));
             *
             * Which means that if nothing else
             * you can handle this in your own
             * middleware.
             */
            failWithError: true
        });

        return handler(req, res, next);

        const auth = req.headers.authorization;

        /**
         * We are not handling this request...
         */
        if(!auth || auth.indexOf('Basic') !== 0) {
            return next();
        }

        let {username, password} = _getAuthObject(auth);

        /**
         * local.login 
         */
        req._passport.instance.login(req, username, password, (error, user, passport)=> {
            if(error) {
                return next(error);
            }

            if(!user) {
                req.session.authenticated = false;
                return res.status(403).json({
                    error: `User ${username} could not be authenticated`
                });
            }

            req.user = user;
            req.session.authenticated = true;
            req.session.passport = passport;
        });
    };
};

function _getAuthObject(auth) {
    auth = _decodeBase64(auth.split(' ')[1]);

    let username = auth.split(':')[0];
    let password = auth.split(':')[1];

    return {
        username,
        password
    };
}

function _decodeBase64(str) {
    return new Buffer(str, 'base64').toString();
}