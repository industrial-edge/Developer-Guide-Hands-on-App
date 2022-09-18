# callbackify
backwards compatibilify your callback functions while migrating apis to promises

## usage
```js
var callbackify = require('callbackify')

var getUserById = callbackify(function (id) {
  // in this example, we're using [minq](https://npm.im/minq)
  return db.users.byId(id).first()
})

// later in your code, we can use a callback

getUserById(23, function (err, user) {
  if (err) { /* give up */ return }
  console.log('hello, ', user.name)
})

// but for newer code, we can consume it as a promise

getUserById(23).then(function (user) {
  console.log('hello, ', user.name)
}, function (err) {
  console.error(err)
})

```
`callbackify` will also preserve the `this` context of your functions:
```js
getUserById.call({foo:true}, 12)
// the underlying promise-returning function is called with the supplied context argument
```

Normally, callbackify will only work with fixed-parameter-length functions, and will use the declared
parameter length to determine if the extra callback argument is present.  If you need to use
callbackify with variadic functions, or functions that don't declare their full argument
list, you can use:
```js
// options argument is optional
var getUserById = callbackify.variadic(function (id, options) {
  if (options === undefined) { options = {} }
  if (options.select) {
    return db.users.byId(id).select(options.select).first()
  } else {
    return db.users.byId(id).first()
  }
})

// we can do either of these
getUserById(23, function (err, user) { })
getUserById(23, { select: [ 'name' ] }, function (err, user) {} )
```
Note that this will not work if the last argument your function can take
is a function, as that last argument will always be detected as a callback
function.

## api

### `callbackify : (fn: (...args) => Promise<T> ) => (...args, Callback<T>) => Promise<T>`

Takes a Promise-returning function `fn` and returns a new function which can return a Promise or take a callback as the last parameter. If a callback is supplied, the function returns void. If no callback is supplied, the promise is returned.

## installation

    $ npm install callbackify


## running the tests

From package root:

    $ npm install
    $ npm test


## contributors

- jden <jason@denizac.org>
- tootallnate <nathan@tootallnate.net>


## license

MIT. (c) MMXIII jden <jason@denizac.org>. See LICENSE.md
