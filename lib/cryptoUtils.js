'use strict';
const Promise = require('bluebird');
const crypto = Promise.promisifyAll(require('crypto'));
const bcrypt = Promise.promisifyAll(require('bcryptjs'));

const SALT_WORK_FACTOR = 10;

function hash(passport, saltWork=SALT_WORK_FACTOR){
    if(!passport.password) return Promise.reject(new Error('Passport has no password'));
    return bcrypt.genSaltAsync(saltWork)
        .then((salt) => bcrypt.hashAsync(passport.password, salt))
        .then((hash) => {
            passport.password = hash;
            return passport;
        });
}
module.exports.hash = hash;


function compare(passport, password=''){
    return bcrypt.compareAsync(password, passport.password);
}

module.exports.compare = compare;


function reset(data, options={}){
    options.tokenExpireAfter = options.tokenExpireAfter || 1 * 60 * 60 * 1000;

    return generateToken().then((token)=>{
        data.resetPasswordToken = token;
        data.resetPasswordExpires = Date.now() + options.tokenExpireAfter;
        return data;
    });
}

module.exports.reset = reset;

/**
 * Update user's password. It will create
 * `resetPasswordToken` and `resetPasswordExpires`.
 * @param  {Object} passport     Passport object.
 * @param  {String} password
 * @return {Promise}
 */
function update(passport, password){
    passport.password = password;
    /*
     * We want to set to `undefined`
     * so that we can update the Model
     * and remove the values from DB.
     */
    passport.resetPasswordToken =
    passport.resetPasswordExpires = undefined;

    return hash(passport);
}
module.exports.update = update;

/**
 * Generate random token. Returns a
 * promise which resolves to the
 * generated token.
 *
 * @param  {Number} [length=40] Token length
 * @return {Promise}
 */
function generateToken(length=40){

    length = Math.round(length/2);

    return crypto.randomBytesAsync(length).then((buffer)=>{
        return buffer.toString('hex');
    });
}

module.exports.generateToken = generateToken;
