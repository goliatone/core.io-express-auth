'use strict';

/**
 * Provide SAML authentication.
 * 
 * It's known to work with **passport-saml**.
 * 
 * @param {Passport} passport Passport instance
 * @param {Object} config Configuraton object
 * @return {Function} Middleware function to handle
 *                    SAML auth.
 */
module.exports = function(passport, config) {
    
    /**
     * 
     * The profile object will look something like this:
     * 
     * ```json
     * {
     * "issuer": "https://app.onelogin.com/saml/metadata/XXXX",
     * "sessionIndex": "_b524d01f-25eb-4f1e-9c1b-7c9e8d3264d4",
     * "nameID": "pepe@rone.com",
     * "nameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
     * }
     *```
     */
    return function $saml(req, profile, next) {
        config.logger.info('Using SAML strategy for user %s', profile.nameID);
        
        /** 
         * This is the query used to create a 
         * new Passport.
        */
        const query = {
            identifier: profile.nameID,
            protocol: 'saml'
        };

        let expectedProfile = {
            email: profile.nameID,
        };

        return passport.connect(req, query, expectedProfile, next);
    };
};
