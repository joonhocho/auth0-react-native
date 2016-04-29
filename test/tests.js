import {expect} from 'chai';
import fetch from 'node-fetch';
global.fetch = fetch;
import Auth0 from '../lib';

/**
 * Test Auth0
 */

describe('Auth0', function() {
  this.timeout(60000);

  it('has a semver tag', (done) => {
    expect(Auth0.clientInfo.version).to.be.a('string');
    done();
  });

  it('has a client information', (done) => {
    expect(Auth0.clientInfo).to.be.a('object');
    done();
  });

  it('sends client information by default', (done) => {
    var auth0 = new Auth0({
      clientID:     'aaaabcdefgh',
      callbackURL: 'https://myapp.com/callback',
      domain:       'aaa.auth0.com'
    });

    auth0._redirect = function (the_url) {
      expect(the_url).to.contain(Auth0.clientInfo.name);
    };

    auth0.login({});

    done();
  });

  it('should not send client information when disabled', function (done) {
    var auth0 = new Auth0({
      clientID:     'aaaabcdefgh',
      callbackURL: 'https://myapp.com/callback',
      domain:       'aaa.auth0.com',
      sendSDKClientInfo: false
    });

    auth0._redirect = function (the_url) {
      expect(the_url).to.not.contain(Auth0.clientInfo.name);
    };

    auth0.login({});

    done();
  });


  it('should support to use signin as an alias for login', function () {
    var auth0 = new Auth0({
      clientID:    'aaaabcdefgh',
      domain:      'aaa.auth0.com',
      callbackURL: 'https://myapp.com/callback',
      callbackOnLocationHash: true
    });

    expect(auth0.signin).to.be.a('function');
    expect(auth0.login).to.be.a('function');
  });


  // TODO SSO
  it.skip('should return empty SSO data after logout', function (done) {
    fetch('https://aaa.auth0.com/logout').then(function () {
      var auth0 = new Auth0({
        clientID:     'aaaabcdefgh',
        callbackURL:  'https://myapp.com/callback',
        domain:       'aaa.auth0.com'
      });

      auth0.getSSOData(function (err, ssoData) {
        expect(ssoData.sso).to.eql(false);
        done();
      });
    });
  });

  describe('Constructor', function () {
    it('should fail to construct without a clientID', function () {
      expect(function () {
        new Auth0({});
      }).to.throw(/clientID is required/);
    });

    it('should not fail to construct without a callbackURL', function () {
      expect(function () {
        new Auth0({clientID: '1123sadsd'});
      }).not.to.throw(/callbackURL is required/);
    });

    it('should fail to construct without a domain', function () {
      expect(function () {
        new Auth0({clientID: '1123sadsd', callbackURL: 'aaaa'});
      }).to.throw(/domain is required/);
    });
  });


  // TODO
  describe.skip('In redirect mode', function () {
    it('should redirect to /authorize with google (callbackOnLocationHash: on)', function (done) {
      var auth0 = new Auth0({
        clientID:    'aaaabcdefgh',
        domain:      'aaa.auth0.com',
        callbackURL: 'https://myapp.com/callback',
        callbackOnLocationHash: true
      });

      auth0._redirect = function (the_url) {
        expect(the_url.split('?')[0])
          .to.contain('https://aaa.auth0.com/authorize');

        var parsed = {};
        the_url.split('?')[1].replace(
          new RegExp('([^?=&]+)(=([^&]*))?', 'g'),
          function($0, $1, $2, $3) { parsed[$1] = decodeURIComponent($3); }
        );

        expect(parsed.response_type).to.equal('token');
        expect(parsed.redirect_uri).to.equal('https://myapp.com/callback');
        expect(parsed.client_id).to.equal('aaaabcdefgh');
        expect(parsed.scope).to.equal('openid');
        done();
      };

      auth0.login({ connection: 'google-oauth2' });
    });

    it('should disable phonegap by default', function () {
      var auth0 = new Auth0({
        clientID:    'aaaabcdefgh',
        callbackURL: 'https://myapp.com/callback',
        domain:      'aaa.auth0.com'
      });

      expect(auth0._useCordovaSocialPlugins).not.to.be.ok();
    });

    it('should redirect to /authorize with values set on login (overriding constructor)', function (done) {
      var auth0 = new Auth0({
        clientID:    'aaaabcdefgh',
        domain:      'aaa.auth0.com',
        callbackURL: 'http://fakeCallback.com',
        callbackOnLocationHash: false
      });

      auth0._redirect = function (the_url) {
        expect(the_url.split('?')[0])
          .to.contain('https://aaa.auth0.com/authorize');

        var parsed = {};
        the_url.split('?')[1].replace(
          new RegExp('([^?=&]+)(=([^&]*))?', 'g'),
          function($0, $1, $2, $3) { parsed[$1] = decodeURIComponent($3); }
        );

        expect(parsed.response_type).to.equal('token');
        expect(parsed.redirect_uri).to.equal('https://myapp.com/callback');
        expect(parsed.client_id).to.equal('aaaabcdefgh');
        expect(parsed.scope).to.equal('openid');
        done();
      };

      auth0.login({
        connection: 'google-oauth2',
        callbackOnLocationHash: true,
        callbackURL: 'https://myapp.com/callback'
      });
    });

    it('should redirect to /authorize with google (callbackOnLocationHash: off)', function (done) {
      var auth0 = new Auth0({
        clientID:     'aaaabcdefgh',
        callbackURL: 'https://myapp.com/callback',
        domain:       'aaa.auth0.com'
      });

      auth0._redirect = function (the_url) {
        expect(the_url.split('?')[0])
          .to.contain('https://aaa.auth0.com/authorize');

        var parsed = {};
        the_url.split('?')[1].replace(
          new RegExp('([^?=&]+)(=([^&]*))?', 'g'),
          function($0, $1, $2, $3) { parsed[$1] = decodeURIComponent($3); }
        );

        expect(parsed.response_type).to.equal('code');
        expect(parsed.redirect_uri).to.equal('https://myapp.com/callback');
        expect(parsed.client_id).to.equal('aaaabcdefgh');
        expect(parsed.scope).to.equal('openid');
        done();
      };

      auth0.login({
        connection: 'google-oauth2'
      });
    });

    it('contains client version information within authorize redirection url', function (done) {
      var auth0 = new Auth0({
        clientID:     'aaaabcdefgh',
        callbackURL: 'https://myapp.com/callback',
        domain:       'aaa.auth0.com'
      });

      auth0._redirect = function (url) {
        expect(url).to.contain(Auth0.clientInfo.name + '=');
        done();
      };

      auth0.login({
        connection: 'google-oauth2'
      });
    })
  });


  describe('getProfile', function () {
    describe('when called with an object', function () {
      it('should call the callback with error', function (done) {
        var auth0 = new Auth0({
          clientID:     'aaaabcdefgh',
          callbackURL:  'https://myapp.com/callback',
          domain:       'aaa.auth0.com'
        });

        auth0.getProfile({foo: 'bar'}).then(done, function (err) {
          expect(err.message).to.equal('Invalid token');
          done();
        });
      });
    });

    describe('when called with an null', function () {
      it('should call the callback with error', function (done) {
        var auth0 = new Auth0({
          clientID:     'aaaabcdefgh',
          callbackURL:  'https://myapp.com/callback',
          domain:       'aaa.auth0.com'
        });

        auth0.getProfile(null).then(done, function (err) {
          expect(err.message).to.eql('Invalid token');
          done();
        });
      });
    });

    describe('from token', function () {

      it('should be able to decode the id_token (if scope=openid profile)', function (done) {
        var auth0 = new Auth0({
          clientID:     '0HP71GSd6PuoRYJ3DXKdiXCUUdGmBbup',
          callbackURL:  'https://myapp.com/callback',
          domain:       'mdocs.auth0.com'
        });

        var result = {
          id_token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL21kb2NzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw0QVpERjU2Nzg5IiwiYXVkIjoiMEhQNzFHU2Q2UHVvUllKM0RYS2RpWENVVWRHbUJidXAiLCJleHAiOjEzOTM5ODMwNDEsImlhdCI6MTM5Mzk0NzA0MSwiY2xpZW50SUQiOiIwSFA3MUdTZDZQdW9SWUozRFhLZGlYQ1VVZEdtQmJ1cCIsImNyZWF0ZWRfYXQiOiJUdWUgTWFyIDA0IDIwMTQgMTU6MzA6NDEgR01UKzAwMDAgKFVUQykiLCJlbWFpbCI6ImpvaG5mb29AZ21haWwuY29tIiwiZmFtaWx5X25hbWUiOiJGb28iLCJnaXZlbl9uYW1lIjoiSm9obiIsImlkZW50aXRpZXMiOlt7InVzZXJfaWQiOiI0QVpERjU2Nzg5IiwicHJvdmlkZXIiOiJhdXRoMCIsImNvbm5lY3Rpb24iOiJ0ZXN0cyIsImlzU29jaWFsIjpmYWxzZX1dLCJuYW1lIjoiSm9obiBGb28iLCJuaWNrbmFtZSI6ImpvaG5mb28iLCJwaWN0dXJlIjoiaHR0cHM6Ly9zZWN1cmUuZ3JhdmF0YXIuY29tL2F2YXRhci8zOGZhMDAyNDIzYmQ4Yzk0MWM2ZWQwNTg4YjYwZmZlZD9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZzc2wuZ3N0YXRpYy5jb20lMkZzMiUyRnByb2ZpbGVzJTJGaW1hZ2VzJTJGc2lsaG91ZXR0ZTgwLnBuZyIsInVzZXJfaWQiOiJhdXRoMHw0QVpERjU2Nzg5IiwibG9naW5Db3VudCI6NywiZm9vIjoiYmFyIn0.sktOHRTH76nylw4qYkv9mFSSV-33I9-75CdT10caJko'
        };

        auth0.getProfile(result.id_token).then(function (profile) {
          expect(profile.name).to.eql('John Foo');
          expect(profile.foo).to.eql('bar');
          expect(profile.identities.length).to.eql(1);
          done();
        }, done);

      });

      it('should be able to take the id_token (scope=openid) and call getUserInfo', function (done) {
        var auth0 = new Auth0({
          clientID:     '0HP71GSd6PuoRYJ3DXKdiXCUUdGmBbup',
          callbackURL:  'https://myapp.com/callback',
          domain:       'mdocs.auth0.com'
        });

        var parseHashResult = {
          id_token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL21kb2NzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw0QVpERjU2Nzg5IiwiYXVkIjoiMEhQNzFHU2Q2UHVvUllKM0RYS2RpWENVVWRHbUJidXAiLCJleHAiOjEzOTM5ODMwMDQsImlhdCI6MTM5Mzk0NzAwNH0.Hh7S4HIPCITag5b0VVF52AA4bWPgVFI2wzgamNzjxUA'
        };

        auth0._getUserInfo = function (profile, id_token) {
          expect(profile.sub).to.eql('auth0|4AZDF56789');
          expect(id_token).to.eql(parseHashResult.id_token);
          done();
        };

        auth0.getProfile(parseHashResult.id_token);
      });

    });
  });


  // TODO
  describe.skip('getSSOData', function () {
    it('should return SSO data', function (done) {
      var auth0 = new Auth0({
        clientID:     'aaaabcdefgh',
        callbackURL:  'https://myapp.com/callback',
        domain:       'aaa.auth0.com'
      });

      auth0.getSSOData(function (err, ssoData) {
        expect(ssoData.sso).to.exist;
        done();
      });
    });
  });

  // TODO
  describe.skip('getConnections', function () {
    it('should return configured connections', function (done) {
      var auth0 = new Auth0({
        domain:      'mdocs.auth0.com',
        callbackURL: 'http://localhost:3000/',
        clientID:    'ptR6URmXef0OfBDHK0aCIy7iPKpdCG4t'
      });

      auth0.getConnections().then((conns) => {
        expect(conns.length).to.be.above(0);
        expect(conns[0].name).to.eql('Apprenda.com');
        expect(conns[0].strategy).to.eql('adfs');
        expect(conns[0].status).to.eql(false);
        expect(conns[0].domain).to.eql('Apprenda.com');
        done();
      }, done);
    });
  });

  describe('getDelegationToken', function () {
    var auth0 = new Auth0({
      domain:      'samples.auth0.com',
      callbackURL: 'http://localhost:3000/',
      clientID:    'BUIJSW9x60sIHBw8Kd9EmCbj8eDIFxDC',
      // forceJSONP:  ('XDomainRequest' in window) //force JSONP in IE8 and IE9
    });

    it('should refresh the token', function (done) {
      var id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImdpdGh1Ynw3MjM3MjMiLCJhdWQiOiJCVUlKU1c5eDYwc0lIQnc4S2Q5RW1DYmo4ZURJRnhEQyIsImlhdCI6MTM5MDUxMjU0OH0.Rd3wjlFhRk6CBzsB371V5x41HITzx5880ezK9rwYzuM';

      auth0.getDelegationToken({
        id_token: id_token,
        api: 'auth0'
      }).then((delegationResult) => {
        expect(delegationResult.id_token).to.exist;
        expect(delegationResult.token_type).to.eql('Bearer');
        expect(delegationResult.expires_in).to.eql(36000);
        done();
      }, done);
    });

    it('should refresh the token when calling refresh as well', function (done) {
      var id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImdpdGh1Ynw3MjM3MjMiLCJhdWQiOiJCVUlKU1c5eDYwc0lIQnc4S2Q5RW1DYmo4ZURJRnhEQyIsImlhdCI6MTM5MDUxMjU0OH0.Rd3wjlFhRk6CBzsB371V5x41HITzx5880ezK9rwYzuM';

      auth0.renewIdToken(id_token).then((delegationResult) => {
        expect(delegationResult.id_token).to.exist;
        expect(delegationResult.token_type).to.eql('Bearer');
        expect(delegationResult.expires_in).to.eql(36000);
        done();
      }, done);
    });

    it('should throw error if no token is sent', function () {
      expect(function () {
        auth0.getDelegationToken(null);
      }).to.throw(/You must send either an id_token or a refresh_token to get a delegation token./);
    });



    it('should return a Firebase token by default since it\'s active', function (done) {
      var id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImdpdGh1Ynw3MjM3MjMiLCJhdWQiOiJCVUlKU1c5eDYwc0lIQnc4S2Q5RW1DYmo4ZURJRnhEQyIsImlhdCI6MTM5MDUxMjU0OH0.Rd3wjlFhRk6CBzsB371V5x41HITzx5880ezK9rwYzuM';

      auth0.getDelegationToken({
        id_token: id_token
      }).then((delegationResult) => {
        expect(delegationResult.id_token).to.exist;
        expect(delegationResult.token_type).to.eql('Bearer');
        expect(delegationResult.expires_in).to.eql(36000);
        done();
      }, done);
    });

    it('should return a Firebase token by default or when asked', function (done) {
      var id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImdpdGh1Ynw3MjM3MjMiLCJhdWQiOiJCVUlKU1c5eDYwc0lIQnc4S2Q5RW1DYmo4ZURJRnhEQyIsImlhdCI6MTM5MDUxMjU0OH0.Rd3wjlFhRk6CBzsB371V5x41HITzx5880ezK9rwYzuM';

      auth0.getDelegationToken({
        id_token: id_token
      }).then((delegationResult) => {
        auth0.getDelegationToken({
          id_token: id_token,
          api: 'firebase'
        }).then((delegationResult2) => {
          expect(delegationResult2.id_token).to.exist;
          expect(delegationResult2.token_type).to.eql('Bearer');
          expect(delegationResult2.expires_in).to.eql(36000);
          done();
        }, done);
      }, done);
    });

  });

  describe('_buildAuthorizeQueryString', function () {
    it('should filter elements in blacklist', function () {
      var blacklist = ['hello', 'foo', 'bar'];

      var queryString = Auth0.prototype._buildAuthorizeQueryString({
        ...{hello: 'world', useful: 'info'},
        ...{foo: 'bar', baz: true},
        ...{bar: 9}
      }, blacklist);

      expect(queryString).to.equal('useful=info&baz=true');
    });

    it('should handle connection_scope array', function () {
      var connection_scope = ['grant1', 'grant2', 'grant3'];

      var queryString = Auth0.prototype._buildAuthorizeQueryString({
        ...{ connection_scope: connection_scope }
      }, []);

      expect(queryString).to.equal('connection_scope=grant1%2Cgrant2%2Cgrant3');
    });

    it('should add offline mode', function () {
      var queryString = Auth0.prototype._buildAuthorizeQueryString({
        ...Auth0.prototype._getMode(),
        ...{ scope: 'openid offline_access'}
      }, []);
      expect(queryString).to.equal('scope=openid%20offline_access&response_type=token&device=ReactNative');
    });

    it('should handle connection_scope string', function () {
      var connection_scope = 'grant1,grant2,grant3';

      var queryString = Auth0.prototype._buildAuthorizeQueryString({
        ...{ connection_scope: connection_scope }
      }, []);

      expect(queryString).to.equal('connection_scope=grant1%2Cgrant2%2Cgrant3');
    });
  });
});
