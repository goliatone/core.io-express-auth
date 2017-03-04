/*jshint esversion:6, node:true*/
'use strict';

const localProtocol = require('./local');

module.exports = function(passport, config){

    return function $basic(req, identifier, password, next){
        config.logger.info('Using basic auth strategy for user %s', identifier);

        return localProtocol.login(req, identifier, password, next);
    };
};
