'use strict';

module.exports = function(passport, config){

    if(!config.logger) config.logger = console;

    return {
        local: require('./local')(passport, config),
        basic: require('./basic')(passport, config),
        bearer: require('./bearer')(passport, config),
        oauth2: require('./oauth2')(passport, config),
        delegated: require('./delegated')(passport, config),
    };
};
