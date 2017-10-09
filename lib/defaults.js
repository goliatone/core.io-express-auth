'use strict';

let config = {
    routes: {
        login: '/login',
        logout: '/logout',
        register: '/register',
        local: '/auth/local',
        localAction: '/auth/local/:action',

        provider: '/auth/:provider',
        providerAction: '/auth/:provider/:action',
        providerCallback: '/auth/:provider/callback'
    }
};

module.exports = config;
