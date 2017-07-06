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
            config.logger.info('redirecting user to %s', redirectOnFailture);
            config.logger.info('should retrun to %s', req.originalUrl);
        }

        if(req.isAuthenticated()) next();
        else {

            /*
             * Here we want the originalUrl since
             * for mounted applications we would not
             * get what we need:
             *
             * ```
             * router.get('/new', AdminController.new);
             * app.use('/admin', router);
             * req.originalUrl /admin/new
             * req.baseUrl /admin
             * req.path /new
             * ```
             */
            config.logger.debug('setup session next: %s', req.originalUrl);
            
            req.session.next = req.originalUrl;
            res.redirect(redirectOnFailture);
        }
    };
};
