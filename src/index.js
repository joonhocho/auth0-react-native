/**
 * Module dependencies.
 */

var Base64Url         = require('./lib/base64_url');
import qs from 'qs';
import {
  decodeToken,
} from 'jwt-node-decoder';



function assert(statement, message) {
  if (!statement) throw new Error(message);
}

function fetchPostJson({url, data, headers}) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(data),
  }).then((response) => response.json());
}

function sanitizeString(str) {
  return str ? str.trim() : '';
}

/**
 * Create an `Auth0` instance with `options`
 *
 * @constructor
 */
export default class Auth0 {
  static clientInfo = {
    name: 'auth0-react-native',
    version: '0.0.1',
  }

  static decodeToken = decodeToken

  constructor({
    clientID,
    domain,
    callbackURL,
    callbackOnLocationHash,
    sendSDKClientInfo,
    device,
  }) {
    assert(clientID, 'clientID is required!');
    assert(domain, 'domain is required!');

    this._clientID = clientID;
    this._domain = domain;
    this._callbackURL = callbackURL;
    this._shouldRedirect = Boolean(callbackURL);
    this._callbackOnLocationHash = callbackOnLocationHash;
    this._sendClientInfo = sendSDKClientInfo == null ? true : sendSDKClientInfo;
    this._device = device || 'Mobile App';
  }


  get clientID() { return this._clientID; }
  get domain() { return this._domain; }
  get tenant() { return this._domain.split('.')[0]; }


  getUrlForEndpoint(endpoint) {
    return `https://${this._domain}/${endpoint}`;
  }

  _getCallbackURL({callbackURL}) {
    return callbackURL === undefined ? this._callbackURL : callbackURL;
  }

  _getClientInfoString() {
    return Base64Url.encode(JSON.stringify(Auth0.clientInfo));
  }

  _getClientInfoHeader() {
    return {
      'Auth0-Client': this._getClientInfoString(),
    };
  }

  /**
   * Resolve response type as `token` or `code`
   *
   * @return {Object} `scope` and `response_type` properties
   * @private
   */
  _getMode(options) {
    return {
      scope: 'openid',
      response_type: this._getCallbackOnLocationHash(options) ? 'token' : 'code',
    };
  }


  _configureOfflineMode(options) {
    const {scope, device} = options;
    if (!device && scope && scope.indexOf('offline_access') >= 0) {
      options.device = this._device;
    }
  }


  /**
   * Get user information from API
   *
   * @param {Object} profile
   * @param {String} id_token
   * @private
   */
  _getUserInfo(profile, id_token) {
    if (!profile || profile.user_id) {
      return Promise.resolve(profile);
    }

    return fetchPostJson({
      url: this.getUrlForEndpoint('/tokeninfo'),
      data: {id_token},
    });
  }


  /**
   * Get profile data by `id_token`
   *
   * @param {String} id_token
   */
  getProfile(id_token) {
    if (!id_token || typeof id_token !== 'string') {
      return Promise.reject(new Error('Invalid token'));
    }

    return this._getUserInfo(decodeToken(id_token), id_token);
  }


  /**
   * Validate a user
   *
   * @param {Object} options
   */
  validateUser(options) {
    return fetchPostJson({
      url: this.getUrlForEndpoint('/public/api/users/validate_userpassword'),
      data: {
        client_id: this._clientID,
        ...options,
        username: sanitizeString(options.username || options.email),
      },
    }).then(
      ({status}) => status === 200,
      (error) => {
        if (error.status === 404) return false;
        throw error;
      }
    );
  }


  /**
   * Signup
   *
   * @param {Object} options Signup Options
   * @param {String} email New user email
   * @param {String} password New user password
   */
  async signup(options) {
    const query = {
      ...this._getMode(options),
      client_id: this._clientID,
      tenant: this.tenant,
      redirect_uri: this._getCallbackURL(options),
      ...options,
      // TODO Change this to a property named 'disableSSO' for consistency.
      // By default, options.sso is true
      sso: options.sso == null ? true : options.sso,
      auto_login: options.auto_login == null ? true : options.auto_login,
      username: sanitizeString(options.username),
      email: sanitizeString(options.email || options.username),
    };

    this._configureOfflineMode(query);

    const response = await fetchPostJson({
      url: this.getUrlForEndpoint('/dbconnections/signup'),
      data: query,
    });

    if (options.auto_login) {
      return this.login(options);
    }
    return response;
  }


  /**
   * Change password
   *
   * @param {Object} options
   */
  changePassword(options) {
    return fetchPostJson({
      url: this.getUrlForEndpoint('/dbconnections/change_password'),
      data: {
        tenant: this.tenant,
        client_id: this._clientID,
        ...options,
        username: sanitizeString(options.username),
        email: sanitizeString(options.email || options.username),
      },
    });
  }


  /**
   * Builds parameter dictionary to be passed to /authorize based on dict key and values.
   *
   * @param {Object} query
   * @param {Array} blacklist
   * @private
   */
  _buildAuthorizationParameters(query, blacklist) {
    // Adds offline mode to the query
    this._configureOfflineMode(query);

    // Adds client SDK information (when enabled)
    if (this._sendClientInfo) {
      query['auth0Client'] = this._getClientInfoString();
    }

    // Elements to filter from query string
    (blacklist || ['popup', 'popupOptions']).forEach((key) => { delete query[key]; });

    if (Array.isArray(query.connection_scope)){
      query.connection_scope = query.connection_scope.join(',');
    }

    return query;
  }


  /**
   * Builds query string to be passed to /authorize based on dict key and values.
   *
   * @param {Object} query
   * @param {Array} blacklist
   * @private
   */
  _buildAuthorizeQueryString(query, blacklist) {
    return qs.stringify(this._buildAuthorizationParameters(query, blacklist));
  }


  _authorize(options) {
    const query = this._buildAuthorizeQueryString({
      ...this._getMode(options),
      client_id: this._clientID,
      redirect_uri: this._getCallbackURL(options),
      ...options,
    });

    return fetch(this.getUrlForEndpoint('/authorize?' + query));
  }


  /**
   * Login user
   *
   * @param {Object} options
   */
  login(options) {
    // TODO Change this to a property named 'disableSSO' for consistency.
    // By default, options.sso is true
    if (options.sso == null) options.sso = true;

    if (options.passcode !== undefined) {
      return this.loginWithPasscode(options);
    }

    if (options.username !== undefined ||
        options.email !== undefined) {
      return this.loginWithUsernamePassword(options);
    }

    return this._authorize(options);
  }


  signin(options) {
    return this.login(options);
  }


  addProfile = (auth) => {
    return this.getProfile(auth.id_token).then((profile) => ({
      auth,
      profile,
    }));
  }


  /**
   * Login with Resource Owner (RO)
   *
   * @param {Object} options
   */
  loginWithResourceOwner(options) {
    const query = {
      ...this._getMode(options),
      client_id: this._clientID,
      grant_type: 'password',
      ...options,
      username: sanitizeString(options.username || options.email),
    };

    this._configureOfflineMode(query);

    return fetchPostJson({
      url: this.getUrlForEndpoint('/oauth/ro'),
      data: query,
      headers: this._getClientInfoHeader(),
    }).then(this.addProfile);
  }


  /**
   * Login with Social Access Token
   *
   * @param {Object} options
   */
  loginWithSocialAccessToken(options) {
    return fetchPostJson({
      url: this.getUrlForEndpoint('/oauth/access_token'),
      data: this._buildAuthorizationParameters({
        scope: 'openid',
        client_id: this._clientID,
        ...options,
      }),
      headers: this._getClientInfoHeader(),
    }).then(this.addProfile);
  }


  /**
   * Login with Username and Password
   *
   * @param {Object} options
   */
  loginWithUsernamePassword(options) {
    if (!options.sso) {
      return this.loginWithResourceOwner(options);
    }

    if (options.sso) {
      return this.loginWithUsernamePasswordAndSSO(options);
    }

    const query = {
      ...this._getMode(options),
      client_id: this._clientID,
      tenant: this.tenant,
      redirect_uri: this._getCallbackURL(options),
      ...options,
      username: sanitizeString(options.username || options.email),
    };

    this._configureOfflineMode(query);

    return fetchPostJson({
      url: this.getUrlForEndpoint('/usernamepassword/login'),
      data: query,
      headers: this._getClientInfoHeader(),
    });
  }


  _verify(options) {
    return fetchPostJson({
      url: this.getUrlForEndpoint('/passwordless/verify'),
      data: options,
      headers: this._getClientInfoHeader(),
    });
  }


  _verify_redirect(options) {
    const query = this._buildAuthorizeQueryString({
      ...this._getMode(options),
      client_id: this._clientID,
      redirect_uri: this._getCallbackURL(options),
      ...options,
    });

    return this._redirect(this.getUrlForEndpoint('/passwordless/verify_redirect?' + query));
  }


  /**
   * Login with phone number and passcode
   *
   * @param {Object} options
   */
  loginWithPasscode(options) {
    const {email, phoneNumber, passcode} = options;
    assert(email != null || phoneNumber != null,
      'email or phoneNumber is required for authentication');

    assert(passcode != null, 'passcode is required for authentication');

    const useSMS = email == null;
    options.connection = useSMS ? 'sms' : 'email';

    if (!this._shouldRedirect) {
      options = {
        ...options,
        username: useSMS ? phoneNumber : email,
        password: passcode,
        sso: false,
      });

      delete options.email;
      delete options.phoneNumber;
      delete options.passcode;

      return this.loginWithResourceOwner(options);
    }

    const verifyOptions = {
      connection: options.connection,
    };

    if (phoneNumber) {
      options.phone_number = phoneNumber;
      verifyOptions.phone_number = phoneNumber;
      delete options.phoneNumber;
    }

    if (email) {
      verifyOptions.email = email;
    }

    options.verification_code = passcode;
    verifyOptions.verification_code = passcode;
    delete options.passcode;

    return this._verify(verifyOptions)
      .then(() => this._verify_redirect(options));
  }


  /**
   * Trigger logout redirect with params from `query` object
   *
   * @example
   *
   *     auth0.logout();
   *     // redirects to -> 'https://yourapp.auth0.com/logout'
   *
   * @example
   *
   *     auth0.logout({returnTo: 'http://logout'});
   *     // redirects to -> 'https://yourapp.auth0.com/logout?returnTo=http://logout'
   *
   * @param {Object} query
   */
  logout(query) {
    let url = this.getUrlForEndpoint('/logout');
    if (query) url += '?' + qs.stringify(query);
    return this._redirect(url);
  }


  /**
   * Get delegation token for certain addon or certain other clientId
   *
   * @example
   *
   *     auth0.getDelegationToken({
   *      id_token:   '<user-id-token>',
   *      target:     '<app-client-id>'
   *      api_type: 'auth0'
   *     }, function (err, delegationResult) {
   *        if (err) return console.log(err.message);
   *        // Do stuff with delegation token
   *        expect(delegationResult.id_token).to.exist;
   *        expect(delegationResult.token_type).to.eql('Bearer');
   *        expect(delegationResult.expires_in).to.eql(36000);
   *     });
   *
   * @example
   *
   *      // get a delegation token from a Firebase API App
   *     auth0.getDelegationToken({
   *      id_token:   '<user-id-token>',
   *      target:     '<app-client-id>'
   *      api_type: 'firebase'
   *     }, function (err, delegationResult) {
   *      // Use your firebase token here
   *    });
   *
   * @param {Object} [options]
   * @param {String} [id_token]
   * @param {String} [target]
   * @param {String} [api_type]
   */
  getDelegationToken(options) {
    assert(options.id_token || options.refresh_token
      'You must send either an id_token or a refresh_token to get a delegation token.');

    const query = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      client_id: this._clientID,
      target: options.targetClientId || this._clientID,
      api_type: options.api,
      ...options,
    };

    delete query.hasOwnProperty;
    delete query.targetClientId;
    delete query.api;

    return fetchPostJson({
      url: this.getUrlForEndpoint('/delegation'),
      data: query,
    });
  }


  renewIdToken(id_token) {
    return this.getDelegationToken({
      id_token,
      scope: 'passthrough',
      api: 'auth0',
    });
  }


  refreshToken(refresh_token) {
    return this.getDelegationToken({
      refresh_token,
      scope: 'passthrough',
      api: 'auth0',
    });
  }


  /**
   * Send email or SMS to do passwordless authentication
   *
   * @example
   *     // To send an email
   *     auth0.startPasswordless({email: 'foo@bar.com'}, function (err, result) {
   *       if (err) return console.log(err.error_description);
   *       console.log(result);
   *     });
   *
   * @example
   *     // To send a SMS
   *     auth0.startPasswordless({phoneNumber: '+14251112222'}, function (err, result) {
   *       if (err) return console.log(err.error_description);
   *       console.log(result);
   *     });
   *
   * @param {Object} options
   */
  startPasswordless(options) {
    const {email, phoneNumber} = options;
    assert(email || phoneNumber,
      'An `email` or a `phoneNumber` is required.');

    const data = {client_id: this._clientID};
    if (email) {
      data.email = email;
      data.connection = 'email';

      if (options.authParams) data.authParams = options.authParams;

      if (!options.send || options.send === 'link') {
        if (!data.authParams) data.authParams = {};

        data.authParams.redirect_uri = this._callbackURL;
        data.authParams.response_type = this._shouldRedirect && !this._callbackOnLocationHash ?
            'code' : 'token';
      }

      if (options.send) data.send = options.send;
    } else {
      data.phone_number = phoneNumber;
      data.connection = 'sms';
    }

    return fetchPostJson({
      url: this.getUrlForEndpoint('/passwordless/start'),
      headers: this._getClientInfoHeader(),
      data,
    });
  }


  requestMagicLink(attrs) {
    return this.startPasswordless(attrs);
  }


  requestEmailCode(attrs) {
    attrs.send = 'code';
    return this.startPasswordless(attrs);
  }


  verifyEmailCode(attrs) {
    attrs.passcode = attrs.code;
    delete attrs.code;
    return this.login(attrs);
  }


  requestSMSCode(attrs) {
    return this.startPasswordless(attrs);
  }


  verifySMSCode(attrs) {
    attrs.passcode = attrs.code;
    delete attrs.code;
    return this.login(attrs);
  }
}
