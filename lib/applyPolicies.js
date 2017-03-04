'use strict';


module.exports = function(route, app, config){
    let policies = config.policies[route] || [];

    policies = policies.map((policy)=>{
        return policy(app, config);
    });

    return policies;
};
