/*jshint esversion:6, node:true*/
'use strict';
const passport = require('passport');
const loadStrategies = require('./strategies/loader');
const _param = require('./param');

module.exports = function(app, config){
    /*
     * Need to validate this!!
     */
    let Passport = config.passport.getPassport();
    let PassportUser = config.passport.getPassportUser();

    /*
     * We need to provide passport with a
     * way to serialize and deserialize
     * a Passport User.
     */
    passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser((id, done) => {
        return PassportUser.findOne(id).then(user => {
            done(null, user);
            return user;
        }).catch(done);
    });

    passport.protocols = require('./protocols')(passport, config);

    /*
     * Extend passport object with an `endpoint`
     * method to handle all 3rd party providers.
     */
    passport.endpoint = function(req, res){
        let strategies = config.passport.strategies;

        let provider = _param(req, 'provider');
        let options = {};

        console.log('passport.endpoint: provider %s', provider);
        /*
         * We did not define the provider.
         */
        if(!strategies.hasOwnProperty(provider)){
            config.logger.warn('passport.endpoint: does not have provider %s', provider);
            return res.redirect('/login');
        }

        ['scope', 'hd', 'display'].map(function(key){
            if(!strategies[provider].options.hasOwnProperty(key)) return;
            options[key] = strategies[provider].options[key];
        });

        this.authenticate(provider, options)(req, res, req.next);
    };

    /*
     * Create an authentication callback endpoint.
     */
    passport.callback = function(req, res, next){
        let action = _param(req, 'action');
        let provider = _param(req, 'provider', 'local');

        console.log('passport:callback provider "%s", action "%s".', provider, action);

        if(action === 'disconnect'){
            if(req.user) return this.disconnect(req, res, next);
            next(new Error('Invalid action'));
        }

        if(provider === 'local' && action !== undefined){
            if(action === 'register' && !req.user){
                console.log('AuthController....');
                return this.protocols.local.register(req, res, next);
            }

            if(action === 'connect' && req.user){
                return this.protocols.local.connect(req, res, next);
            }

            if(action === 'update' && req.user){
                //TODO: Need to make a better flow here.
                return this.protocols.local.update(req, res, next);
            }

            if(action === 'disconnect' && req.user){
                return this.protocols.local.disconnect(req, res, next);
            }

            next(new Error('Invalid action'));

        } else {
            if( action === 'disconnect' && req.user ){
                return this.disconnect(req, res, next);
            }
            console.log('Next: authenticate');
            /*
             *
             */
            this.authenticate(provider, next)(req, res, req.next);
        }
    };

    passport.connect = function(req, query, profile, next){
        let user = {};

        let provider = profile.provider || _param(req, 'provider');

        req.session.tokens = query.tokens;

        query.provider = provider;

        if(!provider){
            return next(new Error('No authentication provider was found.'));
        }

        config.logger.info('auth profile', profile);

        if(profile.emails && profile.emails[0]){
            user.email = profile.emails[0].value;
        }

        //TODO: Make filters!!
        if(config.passport.strategies[provider].restrictToDomain){
            if(!user.email) return false;
            var domain = user.email.split('@')[1];
            var hostedDomain = config.passport.strategies[provider].restrictToDomain;
            hostedDomain = hostedDomain.replace('www.', '');
            if(domain !== hostedDomain){
                return next({status: 401, message: 'Unauthorized domain.'});
            }
        }

        if(profile.username){
            user.username = profile.username;
        }

        if(!user.username && !user.email){
            return next(new Error('Neither email or username was available'));
        }

        Passport.findOne({
            provider: provider,
            identifier: query.identifier.toString()
        }).then((passport)=> {
            //A new user is attempting to sign up using a 3rd
            //party auth provider.
            //Create a ne user and assign them a passport.
            if(!req.user){
                if(!passport){
                    return PassportUser.create(user).then((record)=>{
                        user = record;
                        query.user = user.id;
                        return Passport.create(query);
                    }).then((passport)=>{
                        next(null, user);
                    }).catch(next);
                }
                /*
                 * An existing user is trying to log in using an
                 * already connected passport. Associate user to
                 * passport.
                 * TODO: Ensure we do a proper comparison of tokens
                 */
                if(query.tokens && query.tokens != passport.tokens){
                    passport.tokens = query.tokens;
                }
                return passport.save().then(()=>{
                    return PassportUser.findOne(passport.user);
                }).then((user)=>{
                    next(null, user);
                }).catch(next);
            }
            //User currently logged in, trying to connect a new passport.
            //Create and assing a new passport to the user.
            if(!passport){
                query.user = req.user.id;
                return Passport.create(query).then((passport)=>{
                    next(null, req.user);
                }).catch(next);
            }
            //not sure what's going on here. We do have a session.
            //Just pass it along...Back button?
            next(null, req.user);

        }).catch(next);
    };

    passport.disconnect = function(req, res, next){
        let user = req.user;
        let provider = _param(req, 'provider');

        return Passport.findOne({
            provider: provider,
            user: user.id
        }).then((record)=>{
            return PassportUser.destroy(record.id);
        }).then(()=>{
            next(null, user);
            return user;
        }).catch(next);
    };

    loadStrategies(passport, config.passport.strategies, config);

    return passport;
};