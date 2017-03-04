
const _param = require('./param');


module.exports.init = function(app, config){
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
        register: function(req, res){

            let locals = {
                errors: res.flash('error')
            };

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
        login: function(req, res){
            console.log('strategies', typeof req._passport.instance.strategies);

            let strategies = config.passport.strategies;
            let providers = {};

            Object.keys(strategies).map((key)=>{
                console.log('login: strategy key %s', key);
                if (key === 'local' || key === 'bearer') return;

                providers[key] = {
                    label: strategies[key].label,
                    slug: key
                };
                console.log('provider', providers[key]);
            });

            let locals = {
                providers,
                errors: res.flash('error')
            };

            res.render('login', locals);
        },

        logout: function(req, res){
            /*
             * logout should be handled only
             * by POST methods.
             */
            if(req.method.toUpperCase() !== 'POST'){
                return res.send(400);
            }

            req.logout();
            delete req.user;
            delete req.session.passport;
            req.session.authenticated = false;
            // req.session.destroy((err)=>{
                res.redirect(req.query.next || '/');
            // });
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
        provider: function(req, res){
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
         * It handles three actions:
         * - register
         * - login
         * - disconnect
         *
         */
        callback: function(req, res){
            let _logger = config.logger;

            let action = _param(req, 'action');
            console.log('Req logger', req.logger);
            console.log('AuthController:callback action %s', action);

            req._passport.instance.callback(req, res, (err, user, info, status)=>{
                if(err || !user){
                    _logger.warn(user, err, info, status);
                    return _negotiateError(app, res, err || info, action);
                }

                _logger.info('Login user', user);

                req.login(user, (err)=>{
                    if(err){
                        _logger.warn('AuthController callback', err);
                        return _negotiateError(app, res, err, action);
                    }

                    req.session.authenticated = true;

                    res.locals.user = user;

                    _logger.info('User authenticated OK', user);

                    if(req.query.next){
                        let url = _buildCallbacNextUrl(req);
                        res.status(302).set('Location', url);
                        return res.json(user);
                    }

                    res.redirect((req.session && req.session.returnTo) ? req.session.returnTo : '/');
                });
            });
        },

        /*
         * Disconnect a passport from a user.
         */
        disconnect: function(req, res){
            req._passport.instance.disconnect(req, res);
        }
    }
};

function getView(app, status, defaultView='error'){
    const path = require('path');
    const views = app.get('views');
    const ext = app.get('view engine');
    const exists = require('fs').existsSync;

    const view = path.join(views, status + '.' + ext);

    if(exists(view)) return view;

    if(app.parent) return getView(app.parent, status, defaultView);

    return defaultView;
}

function _negotiateError(app, res, err, action){
    if(action === 'register' || action === 'login'){
        return res.redirect('/' + action);
    } else if(action === 'disconnect'){
        return res.redirect('back');
    }

    res.status(403).format({
        html: function(){
            let view = getView(app, '401');
            res.render(view, {
                message: err.message,
                error: err
            });
        },
        json: function(){
            res.send({
                message: err.message,
                error: err
            });
        }
    });
}

function _buildCallbacNextUrl(req){
    const K = require('gkeypath');

    let url = K.get(req, 'query.next');
    let includeToken = req.query.includeToken;
    let accessToken = K.get(req, 'session.tokens.accessToken');

    if(includeToken && accessToken){
        return url + '?access_token=' + accessToken;
    }

    return url;
}