
## Redirect after login
* `next` keyword in either session or query.

## Authentication Controller

### Login

```js
res.render('login', locals);
```

To customize the login page use `getLocals`. In the configuration file for the module that is calling `core.io-express-auth` add the following:

```js
module.exports = {
    routeLocals: {
        '/login': {
            layout: 'layout-login'
        }
    }
};
```

## Express Locals
* routeLocals: We specify a `locals` object per route.
* locals: This is a global `locals` object that will be merged with `routeLocals` and applied.
