/*jshint esversion:6, node:true*/
'use strict';
/*
 * Bearer Authentication Protocol.
 *
 * Bearer Authentication is for authorizing API requests.
 *
 * When a PassportUser is created we generate an `accessToken`
 * which can be used for API.
 *
 * Sent HTTP header:
 *
 * "Authorization": "Bearer UN2s4fLxo1QmMhOpsK4ZgUvt4"
 *
 * Sent query parameter:
 * ?access_token=UN2s4fLxo1QmMhOpsK4ZgUvt4
 */
module.exports = function(passport, config){
    let Passport = config.passport.getPassport();
    let PassportUser = config.passport.getPassportUser();

    return  function $bearer(req, token, done){

        return Passport.findOne({accessToken: token}).then((passport)=>{

            if(!passport) return done(null, false);

            return PassportUser.findOne({id: passport.user}).then((user)=>{

                if(!user) return done(null, false);

                /*
                 * Prevent from interfering with
                 * model queries...
                 */
                delete req.query.access_token;

                return done(null, user, {scope: 'all'});
            }).catch(done);

        }).catch(done);
    };
};
