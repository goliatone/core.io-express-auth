/*jshint esversion:6, node:true*/
'use strict';

const extend = require('gextend');

function loadStrategies(passport, strategies, config){
    if(!config.logger) config.logger = console;
console.log('loadStrategies...');
    let strategyBean;
    //validate we have at least one strategy.
    if(!strategies || typeof strategies !== 'object' || !Object.keys(strategies).length){
        throw new Error('Need to provide strategies object.');
    }

    Object.keys(strategies).map((key)=>{

        strategyBean = strategies[key];
        //TODO: validate. We need following keys:
        //strategy
        if(!strategyBean.strategy) throw new Error('Invalid strategy bean. Missing strategy.');
        if(!strategyBean.protocol) throw new Error('Invalid strategy bean. Missing protocl.');

        config.logger.info('Loading strategy bean "%s".', key);

        let options = {
            passReqToCallback: true
        };

        let Strategy;

        if(key === 'local'){
            console.log('register local strategy');

            // successRedirect
            // failureRedirect
            // failureFlash

            options = extend({
                // passwordField
                passReqToCallback: true,
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
            callback = require('path').join('auth', key, 'callback');
        }

        Strategy = strategyBean.strategy;

        let baseUrl = '';

        if(config.baseUrl){
            baseUrl = config.baseUrl;
        } else {
            throw new Error('Please set baseUrl configuration value!');
        }

        const url = require('url');

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

        passport.use(new Strategy(options, passport.protocols[protocol]));
    });
}

module.exports = loadStrategies;
