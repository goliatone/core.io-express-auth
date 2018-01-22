'use strict';

/**
 * OpenID authentication protocol
 * 
 * @param {Passport} passport Passport instance
 * @param {Object} config Configuration object
 */
module.exports = function(passport, config) {

    /**
     * 
     * @param {http.Request} req Express request object
     * @param {String} identifier Profile identifier
     * @param {Ojbect} profile User profile
     * @param {Function} next Express middleware next
     */
    return function $openid(req, identifier, profile, next) {
        const query = {
            identifier,
            protocol: 'openid'
        };

        return passport.connect(req, query, profile, next);
    };
};