'use strict';

const extend = require('gextend');
const express = require('express');
const Keypath = require('gkeypath');

const AuthController = require('./lib/AuthController');
const extendPassport = require('./lib/extendPassport');

/**
 * Provide Passport.js support for our
 * core.io-express-server application.
 * The `app` paramter can be an Express app
 * or, more likely, a subapp.
 *
 * @method exports
 * @param  {Object} app    Express app or subapp
 * @param  {Object} config config.server value.
 * @return {void}
 */
module.exports = function(app, config) {
    
    if(!config.logger) config.logger = console;

    config.logger.info('======> passport');
    config.logger.info(Object.keys(config));

    let passport = extendPassport(app, config);

    /*
     * Initialize session passport
     * We should be able to move this to the
     * auth submodule and pull from there.
     * This HAS to come before registering
     * router or app routes...
     */
    app.use(passport.initialize());

    app.use(passport.session());

    /*
     * Create all default routes so we can handle
     * authentication flow:
     * - login
     * - logout
     */
    let router = express.Router();

    let authController = AuthController.init(app, config);

    router.get('/login', authController.login);
    //TODO: config.routes.logout;
    router.get('/logout', authController.logout);

    /// THIS SHOULD BE OPTIONAL ////////////
    router.get('/register', authController.register);

    //This is equivalment to: /login
    router.post('/auth/local', authController.callback);
    router.post('/auth/local/:action', authController.callback);

    router.post('/auth/:provider', authController.callback);
    router.post('/auth/:provider/:action', authController.callback);

    router.get('/auth/:provider', authController.provider);
    router.get('/auth/:provider/callback', authController.callback);
    router.get('/auth/:provider/:action', authController.callback);

    /*
     * Use all declared strategies
     */
    app.use('/', router);
};

module.exports.policies = require('./lib/policies');

module.exports.cryptoUtils = require('./lib/cryptoUtils');

module.exports.applyPolicies = require('./lib/applyPolicies');
