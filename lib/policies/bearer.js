'use strict';

const Keypath = require('gkeypath');

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
module.exports = function(app, config) {

    return function $bearer(req, res, next) {
        let passport = req._passport.instance;

        /*
         * Note that we are not overwritting the raw headers.
         * Meaning there might be a mismatch between the headers
         * accept and the raw headers.
         * 
         * This is a sample of what headers could look like:
         * 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,* / *;q=0.8',
         */
        let setHeaders = Keypath.get(req, 'headers.accept', false);

        if(setHeaders) {
            if(setHeaders.indexOf('json') === -1) {
                setHeaders = 'application/json,' + setHeaders;
            }
        } else {
            setHeaders = 'application/json';
        }

        Keypath.set(req, 'headers.accept', setHeaders);

        let handler = passport.authenticate('bearer', {
            session: false,
            /*
             * We want to bubble up errors,
             * this makes passport to fail with
             * next(new AuthoriaztionError(mesage));
             *
             * Which means that if nothing else
             * you can handle this in your own
             * middleware.
             */
            failWithError: true
        });

        return handler(req, res, next);
    };
};
