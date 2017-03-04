'use strict';
const Keypath = require('gkeypath');

module.exports = function appVariables(app, config){

    let redirectOnFailture = Keypath.get(config, 'redirectOnFailture', '/login');

    return function $isAuthenticated(req, res, next){

        if(req.isAuthenticated()) next();
        else {
            req.session.next = req.path;
            res.redirect(redirectOnFailture);
        }
    };
};
