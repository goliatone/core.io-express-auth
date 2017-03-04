## core.io-auth


#### Routes

- `GET  /login`: Show login form.
- `POST /login`: Handle local strategy login.
- `GET  /logout`: Destroy session.
- `GET  /signup`: Show signup form.
- `POST /signup`:
- `GET /auth/:`


- `POST /register`: 'UserController.create',
- `POST /logout`:  'AuthController.logout',

- `POST /auth/local`: 'AuthController.callback',
- `POST /auth/local/:action`: 'AuthController.callback',

- `POST /auth/:provider`: 'AuthController.callback',
- `POST /auth/:provider/:action`: 'AuthController.callback',

- `GET /auth/:provider`: 'AuthController.provider',
- `GET /auth/:provider/callback`: 'AuthController.callback',
- `GET /auth/:provider/:action`: 'AuthController.callback'


### TODO
- [ ] Manage locals index.js L-482
- [ ] Pull routes from config
- [ ] Normalize config:
    - config.passport -> config
- [ ] Make filters so that we handle `restrictToDomain` as a generic filter
    - i.e check that a user who's been banned doesn't log in again.
- [ ] Check how we should use scope in oAuth2 to restrict by domain.


<!--
https://github.com/trailsjs/sails-permissions
-->
