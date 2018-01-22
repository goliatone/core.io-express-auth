'use strict';

const url = require('url');
const {join} = require('path');
const extend = require('gextend');

function loadStrategies(passport, strategies, config) {
    if(!config.logger) config.logger = console;

    let strategyBean;
    //validate we have at least one strategy.
    if(!strategies || typeof strategies !== 'object' || !Object.keys(strategies).length) {
        throw new Error('Need to provide strategies object.');
    }

    Object.keys(strategies).map((key) => {

        strategyBean = strategies[key];
        
        if(!strategyBean.strategy) throw new Error('Invalid ' + key + ' strategy bean. Missing strategy.');
        if(!strategyBean.protocol) throw new Error('Invalid ' + key + ' strategy bean. Missing protocl.');

        config.logger.info('Loading auth strategy bean "%s".', key);

        let options = {
            passReqToCallback: true
        };

        let Strategy;

        if(key === 'local') {
            console.log('register local strategy');

            // successRedirect
            // failureRedirect
            // failureFlash

            options = extend(options, {
                // passwordField
                usernameField: 'identifier'
            });

            if(strategies.local){
                console.log('Actually use local strategy...');
                Strategy = strategyBean.strategy;
                passport.use(new Strategy(options, passport.protocols.local.login));
            }
            return;
        }

        let protocol = strategyBean.protocol;
        let callback = strategyBean.callback;

        if(!callback){
            callback = join('auth', key, 'callback');
        }

        Strategy = strategyBean.strategy;

        let baseUrl = '';

        if(config.baseUrl) {
            baseUrl = config.baseUrl;
        } else {
            throw new Error('Please set baseUrl configuration value!');
        }

        /**
         * Do some default setup per protocol 
         * type. You can alway override these 
         * with the `strategy.<protocol>.<options>`
         * object.
         */
        switch (protocol) {
            case 'oauth':
            case 'oauth2':
                options.callbackURL = url.resolve(baseUrl, callback);
                break;
            case 'openid':
                options.returnURL = url.resolve(baseUrl, callback);
                options.realm = baseUrl;
                options.profile = true;
                break;
        }

        options = extend(options, strategyBean.options);

        /** 
         * This function will do the actual authentication.
         * e.g. bearer protocol with try to find a user by token.
         * e.g. local will find user by username/email and validate 
         * password.
         * 
        */
        let athenticationFunction = passport.protocols[protocol];

        passport.use(new Strategy(options, athenticationFunction));
    });
}

module.exports = loadStrategies;
