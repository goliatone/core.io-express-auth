/*jshint esversion:6, node:true*/
'use strict';
const passport = require('passport');
const loadStrategies = require('./strategies/loader');
const _param = require('./param');

module.exports = function(app, config) {

    let Passport = config.passport.getPassport();
    let PassportUser = config.passport.getPassportUser();

    if (!Passport) throw new Error('Auth module needs Passport model defined');
    if (!PassportUser) throw new Error('Auth module needs PassportUser model defined');

    /*
     * We need to provide passport with a
     * way to serialize and deserialize
     * a Passport User.
     */
    passport.serializeUser((user, done) => done(null, user.id));

    /*
     * If we have sub-apps, this function will
     * called multiple times. Not ideal behaviour.
     * http://stackoverflow.com/questions/7650981/how-to-share-sessions-in-mounted-express-apps
     */
    passport.deserializeUser((id, done) => {

        config.logger.info('passport.deserializeUser(%s)', id);

        return PassportUser.findOne(id).then(user => {
            config.logger.info('Result user: %j', user);
            done(null, user);
            return user;
        }).catch((err)=>{
            config.logger.error('PassportUser.findOne(%s)', id);
            config.logger.error(err.message);
            done(err);
        });
    });

    passport.protocols = require('./protocols')(passport, config);

    /*
     * Extend passport object with an `endpoint`
     * method to handle all 3rd party providers.
     */
    passport.endpoint = function(req, res, next) {
        let strategies = config.passport.strategies;

        let provider = _param(req, 'provider');
        let options = {};

        /*
         * We did not define the provider.
         */
        if (!strategies.hasOwnProperty(provider)) {
            config.logger.error('passport.endpoint: does not have provider %s', provider);
            if(process.env.NODE_ENV === 'production') {
                return res.redirect('/login');
            }
            req.next(new Error('Unsupported provider'));
        }

        ['scope', 'hd', 'display'].map(key => {
            if (!strategies[provider].options.hasOwnProperty(key)) return;
            options[key] = strategies[provider].options[key];
        });

        this.authenticate(provider, options)(req, res, req.next);
    };

    /*
     * Create an authentication callback endpoint.
     */
    passport.callback = function(req, res, next) {
        let action = _param(req, 'action');
        let provider = _param(req, 'provider', 'local');

        if (action === 'disconnect') {
            if (req.user) return this.disconnect(req, res, next);
            next(new Error('Invalid action'));
        }

        if (provider === 'local' && action !== undefined) {
            if (action === 'register' && !req.user) {
                return this.protocols.local.register(req, res, next);
            }

            if (action === 'connect' && req.user) {
                return this.protocols.local.connect(req, res, next);
            }

            if (action === 'update' && req.user) {
                //TODO: Need to make a better flow here.
                return this.protocols.local.update(req, res, next);
            }

            if (action === 'disconnect' && req.user) {
                return this.protocols.local.disconnect(req, res, next);
            }

            next(new Error('Invalid action'));

        } else {
            if (action === 'disconnect' && req.user) {
                return this.disconnect(req, res, next);
            }

            /*
             *
             */
            this.authenticate(provider, next)(req, res, req.next);
        }
    };

    passport.connect = function(req, query, profile, next) {

        let _extendUser = function(o, user, profile){
            if(typeof o.handleUserProfile === 'function'){
                o.handlePassportUserProfile(user, profile);
            }
        };

        let user = {};

        let provider = profile.provider || _param(req, 'provider');

        req.session.tokens = query.tokens;

        query.provider = provider;

        if (!provider) {
            return next(new Error('No authentication provider was found.'));
        }

        config.logger.info('auth profile', profile);

        /**
         * This is how oauth2 sends user profile 
         * info.
         */
        if (profile.emails && profile.emails[0]) {
            user.email = profile.emails[0].value;
        }

        /**
         * This is6 how SAML sends user profile
         * info.
         */
        if(profile.email) {
            user.email = profile.email;
        }

        //TODO: Make filters!!
        if (config.passport.strategies[provider].restrictToDomain) {
            if (!user.email) return false;
            let domain = user.email.split('@')[1];
            let hostedDomain = config.passport.strategies[provider].restrictToDomain;
            hostedDomain = hostedDomain.replace('www.', '');
            if (domain.toLowerCase() !== hostedDomain.toLowerCase()) {
                return next({
                    status: 401,
                    message: 'Unauthorized domain.'
                });
            }
        }

        if (profile.username) {
            user.username = profile.username;
        }

        if (!user.username && !user.email) {
            return next(new Error('Neither email or username was available'));
        }

        /*
         * If the used PassportUser wants to store different
         * information from the user's profile, we can pass
         * the user object and the profile before we call
         */
        _extendUser(config.passport, user, profile);

        let identifier = query.identifier.toString();

        config.logger.info('auth: Passport.findOne({provider:"%s", identifier: "%s"})', provider, identifier);

        Passport.findOne({
            provider: provider,
            identifier: identifier
        }).then((passport) => {
            /*
             * A new user is attempting to sign up using a 3rd
             * party auth provider.
             */
            if (!req.user) {
                /*
                 * First time user.
                 * Create a ne user and assign them a passport.
                 */
                if (!passport) {
                    return PassportUser.create(user).then((record) => {
                        user = record;
                        query.user = user.id;
                        return Passport.create(query);
                    }).then((passport) => {
                        next(null, user);
                    }).catch(next);
                }

                /*
                 * An existing user is trying to log in using an
                 * already connected passport. Associate user to
                 * passport.
                 * TODO: Ensure we do a proper comparison of tokens
                 */
                if (query.tokens && query.tokens != passport.tokens) {
                    // config.logger.info('update passport.tokens');
                    passport.tokens = query.tokens;
                }

                return passport.save().then(() => {
                    // config.logger.info('auth: Passport.findOne(%j)', passport.user);
                    return PassportUser.findOne(passport.user);
                }).then((user) => {
                    // console.log('passport.save().then', user);
                    /*
                     * Extend session user with app logic
                     */
                    _extendUser(config.passport, user, profile);
                    next(null, user);
                }).catch(next);
            }
            /*
             * User currently logged in, trying to connect
             * a new passport. Create and assing a new
             * passport to the user.
             */
            if (!passport) {
                query.user = req.user.id;
                return Passport.create(query).then((passport) => {
                    next(null, req.user);
                }).catch(next);
            }
            //not sure what's going on here. We do have a session.
            //Just pass it along...Back button?
            next(null, req.user);

        }).catch((err) => {
            config.logger.error('Passport.findOne({provider:"%s", identifier: "%s"})', provider, identifier);
            config.logger.error(err.message);
            next(err);
        });
    };

    passport.disconnect = function(req, res, next) {
        let user = req.user;
        let provider = _param(req, 'provider');

        return Passport.findOne({
            provider: provider,
            user: user.id
        }).then((record) => {
            return PassportUser.destroy(record.id);
        }).then(() => {
            next(null, user);
            return user;
        }).catch(next);
    };

    loadStrategies(passport, config.passport.strategies, config);

    return passport;
};
