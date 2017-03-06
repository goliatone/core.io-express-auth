/*jshint esversion:6, node:true*/
'use strict';

const Keypath = require('gkeypath');

module.exports = function appVariables(app, config){
    if(!config.logger) config.logger = console;

    let redirectOnFailture = Keypath.get(config, 'redirectOnFailture', '/login');

    return function $isAuthenticated(req, res, next){
        if(app.get('env') === 'development'){
            config.logger.info('isAuthenticated?', req.isAuthenticated());
            config.logger.info('user:', req.user);
        }

        if(req.isAuthenticated()) next();
        else {
            req.session.next = req.path;
            res.redirect(redirectOnFailture);
        }
    };
};
