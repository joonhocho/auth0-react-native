# auth0-react-native
[![Build Status](https://travis-ci.org/joonhocho/auth0-react-native.svg?branch=master)](https://travis-ci.org/joonhocho/auth0-react-native)
[![Coverage Status](https://coveralls.io/repos/github/joonhocho/auth0-react-native/badge.svg?branch=master)](https://coveralls.io/github/joonhocho/auth0-react-native?branch=master)
[![npm version](https://badge.fury.io/js/auth0-react-native.svg)](https://badge.fury.io/js/auth0-react-native)
[![Dependency Status](https://david-dm.org/joonhocho/auth0-react-native.svg)](https://david-dm.org/joonhocho/auth0-react-native)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

React Native (possibly Node.js) port of [auth0/auth0.js](https://github.com/auth0/auth0.js).


### It's currently WORK IN PROGRESS
It has not been tested yet on React Native. Currently, 60% of unit tests are passing.

So don't create an issue, but rather create a PR for me! Thanks!


### How it differs from [node-auth0](https://github.com/auth0/node-auth0) and [auth0.js](https://github.com/auth0/auth0.js).
`node-auth0` is for node.js, but it lacks client APIs such as `signup`, `login`, `renewIdToken`, `getDelegationToken`, ...
Because, it assumes you are a server, not a client.

`auth0.js` supports client APIs, but is for a browser environment. It depends on browser specific variables such as `window`, `navigator`, `popup`, ...

`auth0-react-native` is for React Native Apps, (can easily configured to support Node.js as well since both share very similar environments).

Note that since it is not for a browser, it does not support any popup related APIs and cross-origin related parameters.


### Install
```
npm install --save auth0-react-native
```


### Usage
```javascript
import Auth0 from 'auth0-react-native';

const auth0 = new Auth0({
  domain:       'mine.auth0.com',
  clientID:     'dsa7d77dsa7d7',
});

// We do not support callbacks.
// Use Promise everywhere.
auth0.login({
  connection: 'db-conn',
  username:   'USERNAME_INPUT_FROM_USER',
  password:   'PASSWORD_INPUT_FROM_USER',
}).then((response) => {
  const {auth: {id_token, access_token}, profile} = response;
  // Use id_token, access_token, profile.
});
```

For other APIs, please take a look at [tests](https://github.com/joonhocho/auth0-react-native/tree/master/test).

Also, visit [auth0/auth0.js](https://github.com/auth0/auth0.js).

APIs are almost identical as auth0.js, except that we use `Promise`, not callbacks.


### TODO
Please help with Pull Requests!

 - SSO?
 - Pass Passwordless tests
 - Test on React Native iOS
 - Make compatible with Node
 - Documentation


### Dependencies
 - Encoding Base64: https://github.com/jsdom/abab
 - Decoding JWT: https://github.com/joonhocho/jwt-node-decoder
 - Constructing Query String: https://github.com/ljharb/qs


### LICENSE
```
The MIT License (MIT)

Copyright (c) 2016 Joon Ho Cho

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
