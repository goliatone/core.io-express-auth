/*jshint esversion:6, node:true*/
'use strict';

const extend = require('gextend');
const _param = require('./param');
const Keypath = require('gkeypath');

//TODO: Add extension mechanism so we can take it from
//config object.
//return extend({}, {register:...}, config.authController);
module.exports.init = function(app, config) {
    /*
     * ROUTES:
     * POST /register UserController.create
     * POST /logout AuthController.logout
     *
     * POST /auth/local AuthController.callback
     * POST /auth/local/:action AuthController.callback
     *
     * POST /auth/:provider AuthController.callback
     * POST /auth/:provider/:action AuthController.callback
     *
     * GET /auth/:provider AuthController.provider
     * GET /auth/:provider/callback AuthController.callback
     * GET /auth/:provider/:action AuthController.callback
     *
     * GET /auth/google AuthController.provider
     * GET /auth/google/callback AuthController.callback
     * GET /auth/google/create AuthController.callback
     */
    return {
        /**
         * We want to only enable this to ppl we want to offer
         * a registration token.
         * A) Create token, send link with token
         * B) Check token vs database, if valid show
         * C) Send to token expired
         *
         * Render the registration page
         *
         * Just like the login form, the registration form is just simple HTML:
         *
        <form role="form" action="/auth/local/register" method="post">
          <input type="text" name="username" placeholder="Username">
          <input type="text" name="email" placeholder="Email">
          <input type="password" name="password" placeholder="Password">
          <button type="submit">Sign up</button>
        </form>
        *
        * @param {Object} req
        * @param {Object} res
        */
        register: function(req, res) {

            let locals = getLocals('/login', config, req);

            extend(locals, {
                errors: res.flash('error')
            });

            res.render('register', locals);
        },

        /**
         * Render the login page
         *
         * The login form itself is just a simple HTML form:
         *
            <form role="form" action="/auth/local" method="post">
                <input type="text" name="identifier" placeholder="Username or Email">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Sign in</button>
            </form>
         *
         * You could optionally add CSRF-protection as outlined in the documentation:
         * http://sailsjs.org/#!documentation/config.csrf
         *
         * A simple example of automatically listing all available providers in a
         * Handlebars template would look like this:
         *
            {{#each providers}}
                <a href="/auth/{{slug}}" role="button">{{name}}</a>
            {{/each}}
         */
        login: function(req, res) {

            let user = Keypath.get(req, 'session.passport.user', false);

            if (user) {
                let redirectURL = Keypath.get(req, 'session.next', '/');
                return res.redirect(redirectURL);
            }

            let strategies = config.passport.strategies;
            let providers = {};

            Object.keys(strategies).map((key) => {
                // if (key === 'local' || key === 'bearer' || key === 'basic') return;
                if (['local', 'bearer', 'basic'].includes(key)) return;

                providers[key] = {
                    label: strategies[key].label,
                    slug: key
                };
            });

            let locals = getLocals('/login', config, req);

            extend(locals, {
                providers,
                errors: res.flash('error')
            });

            res.render('login', locals);
        },

        logout: function(req, res) {
            /*
             * logout should be handled only
             * by POST methods.
             */
            // if (req.method.toUpperCase() !== 'POST') {
            //     return res.send(400);
            // }

            req.logout();

            delete req.user;
            delete req.session.passport;
            req.session.authenticated = false;

            let redirectURL = Keypath.get(req, 'session.next', '/');
            res.redirect(redirectURL);
        },

        /*
         * Creates a 3rd party authentication
         * endpoint.
         *
         * i.e. GET /auth/google
         *
         * This basically calls `passport.authenticate`
         * which would redirect user to the provider
         * for authentication.
         * On complete, the provider must redirect
         * the user back to /auth/:provider/callback
         */
        provider: function(req, res) {
            //TODO: get passport from context?! Or pass
            //when we create AuthController...
            req._passport.instance.endpoint(req, res);
        },

        /*
         * Authentication callback endpoint.
         * Handles creating and verifying `Passport`s
         * and `PassportUser`s, both locally and 3rd
         * party.
         *
         * It handles the following routes:
         * - `POST /auth/:provider`: 'AuthController.callback'
         * - `POST /auth/:provider/:action`: 'AuthController.callback'
         *
         * - `GET /auth/:provider/callback`: 'AuthController.callback'
         * - `GET /auth/:provider/:action`: 'AuthController.callback'
         *
         * An example of a provider would be:
         *
         * - `POST /auth/local`: 'AuthController.callback'
         * - `POST /auth/local/:action`: 'AuthController.callback'
         */
        callback: function(req, res) {
            let _logger = config.logger;

            let action = _param(req, 'action');

            req._passport.instance.callback(req, res, (err, user, info, status) => {
                if (err || !user) {
                    if (!err) err = {
                        message: info
                    };

                    _logger.warn('AuthController.callback(action: %s): user %s err %j info %s status %s', action, user, err, info, status);
                    return _negotiateError(app, res, err || info, action, status);
                }

                _logger.info('Login user: %j', user);

                req.login(user, (err) => {
                    if (err) {
                        _logger.err('AuthController callback', err);
                        return _negotiateError(app, res, err, action);
                    }
                    console.log('----- REQ LOGIN, setup user', user);
                    req.session.authenticated = true;

                    res.locals.user = user;

                    // if(req.wantsJSON()){
                    //     let url = _buildCallbacNextUrl(req);
                    //     res.status(302).set('Location', url);
                    //     return res.json(user);
                    // }
                    let redirectURL = Keypath.get(req, 'session.next', '/');
                    console.log('redirectURL %s', redirectURL);

                    res.redirect(redirectURL);
                });
            });
        },

        /*
         * Disconnect a passport from a user.
         */
        disconnect: function(req, res) {
            req._passport.instance.disconnect(req, res);
        }
    }
};

function getLocals(route, config, req) {
    let routeLocals = Keypath.get(config, 'routeLocals', {});
    return extend({}, config.locals, req.locals, routeLocals[route]);
}

/**
 * This function will try to return a valid path to
 * a view.
 *
 * It will recursively call itself while the provided
 * express instance has a `parent` attribute.
 *
 * @TODO: Consolidate with core.io-express-server/lib/getView
 * @TODO: Move to it's own package.
 *
 * @param  {Object} app                   Express instance
 * @param  {String} viewName              View name without ext
 * @param  {String} [defaultView='error']
 * @return {String}                       Path to a valid view.
 */
function getView(app, viewName, defaultView = 'error') {
    const path = require('path');
    const exists = require('fs').existsSync;

    let views = app.get('views');
    const ext = app.get('view engine');

    if (!Array.isArray(views)) views = [views];

    let view;
    for (var i = 0; i < views.length; i++) {
        view = path.join(views[i], viewName + '.' + ext);
        if (exists(view)) return view;
    }

    if (app.parent) return getView(app.parent, viewName, defaultView);

    return defaultView;
}

function _negotiateError(app, res, err, action, status = 401) {
    if (action === 'register' || action === 'login') {
        return res.redirect('/' + action);
    } else if (action === 'disconnect') {
        return res.redirect('back');
    }

    if (!err) {
        err = {
            mesage: ''
        };
    }

    // if (stats == 401 && challenge.length) {
    //     res.setHeader('WWW-Authenticate', challenge);
    // }

    res.status(status).format({
        html: function() {
            let view = getView(app, status, '401');
            let layout = getView(app, 'error-layout', false);

            let locals = {
                isErrorView: true,
                status: status,
                message: err.message,
                error: err
            };

            /*
             * to set express-ejs-layouts layout
             * we just give it the name.
             */
            if (layout) locals.layout = 'error-layout';

            res.render(view, locals);
        },
        json: function() {
            res.send({
                message: err.message,
                error: err
            });
        }
    });
}

function _buildCallbacNextUrl(req) {
    const K = require('gkeypath');

    let url = K.get(req, 'query.next');
    let includeToken = req.query.includeToken;
    let accessToken = K.get(req, 'session.tokens.accessToken');

    if (includeToken && accessToken) {
        return url + '?access_token=' + accessToken;
    }

    return url;
}