/*jshint esversion:6, node:true*/
'use strict';

/*
 * OAuth 2.0 Authentication Protocol
 *
 * OAuth 2.0 is the successor to OAuth 1.0, and is designed to overcome
 * perceived shortcomings in the earlier version. The authentication flow is
 * essentially the same. The user is first redirected to the service provider
 * to authorize access. After authorization has been granted, the user is
 * redirected back to the application with a code that can be exchanged for an
 * access token. The application requesting access, known as a client, is iden-
 * tified by an ID and secret.
 */
module.exports = function(passport, config){

    return function $oauth2(req, accessToken, refreshToken, profile, next){
        config.logger.info('Using oauth auth strategy for user %s', profile.id);

        let query = {
            identifier: profile.id,
            protocol: 'oauth2',
            tokens: {accessToken}
        };

        if(refreshToken){
            query.tokens.refreshToken = refreshToken;
        }

        return passport.connect(req, query, profile, next);
    };
};
