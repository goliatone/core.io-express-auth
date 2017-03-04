function _param(req, name, def){
    var body = req.body || {};
    var query = req.query || {};
    var params = req.params || {};

    if (null != params[name] && params.hasOwnProperty(name)) return params[name];
    if (null != body[name]) return body[name];
    if (null != query[name]) return query[name];

    return def;
}
module.exports = _param;
