/*jshint esversion:6, node:true*/
'use strict';

/*
 * Delegated Authentication Protocol
 *
 * Authentication is delegated by the Strategy to an external provider
 * but handled locally (e.g. makes request internally to external provider)
 * unlike OAuth or similar which redirects to the external provider.
 * On success the authenticated user is connected to a local user (created if
 * necessary) in a similar manner to OAuth.
 */
module.exports = function(passport, config){

    return function $delegated(req, profile, next){
        config.logger.info('Using delegated auth strategy for user %s', profile.id);

        let query = {
            identifier: profile.id,
            protocol: 'delegated'
        };

        return passport.connect(req, query, profile, next);
    };
};
