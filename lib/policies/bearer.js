'use strict';

/**
 * Policy for authorizing API requests. The request
 * will be authenticated if it contins an `accessToken`
 * in the headers, or an `access_token` accessible to
 * params.
 * It will not create a session.
 *
 * `'Authorization': 'Bearer 7JceWkCWi7BoDEj420ea9sxDO1t2MQopi9d_NXome2tP9D6v2DOv3rzTBpuGUuZJ'`
 *
 * `?access_token=7JceWkCWi7BoDEj420ea9sxDO1t2MQopi9d_NXome2tP9D6v2DOv3rzTBpuGUuZJ`
 * @param  {Object}   req
 * @param  {Object}   res
 * @param  {Function} next
 */
module.exports = function(app, config){

    return function $bearer(req, res, next){
        let passport = req._passport.instance;
        return passport.authenticate('bearer', {session: false})(req, res, next);
    };
};
