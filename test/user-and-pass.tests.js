import {expect} from 'chai';
import fetch from 'node-fetch';
global.fetch = fetch;
import Auth0 from '../lib';
import sinon from 'sinon';
import {failPromise} from './util';


/**
 * XHR support variables
 */

var xhrSupport = !(new Auth0({clientID: 'clientID', domain: 'domain'}))._useJSONP;
var xhrSupportPrefix = xhrSupport ? '' : 'not ';

/**
 * Test User and Password
 */

describe('Auth0 - User And Passwords', function () {
  this.timeout(5000);

  const auth0 = new Auth0({
    domain:      'mdocs.auth0.com',
    callbackURL: 'http://localhost:3000/',
    clientID:    'ptR6URmXef0OfBDHK0aCIy7iPKpdCG4t'
  });

  describe('Login', () => {
    describe('with resource owner', () => {
      it('should call the callback when user/pass is wrong', (done) => {
        auth0.login({
          connection: 'tests',
          username: 'testttt@wrong.com',
          password: '12345',
          sso: false,
        }).then(failPromise(done), (err) => {
          expect(err.status).to.equal(401);
          expect(err.details.code).to.equal('invalid_user_password');
          done();
        });
      });

      // Fails on IE8. Some bug with errors on XMLHttpRequest handling
      // XXX: Fix it!
      /*
      it.skip('should call the callback with err when the connection doesn\'t exists', function (done) {
        auth0.login({
          connection: 'testsw3eeasdsadsa',
          username: 'testttt@wrong.com',
          password: '12345',
          sso:      false
        }, function (err, profile) {
          expect(err.status).to.equal(400);
          expect(err.message).to.equal('invalid_connection');
          expect(profile).not.to.be.ok;
          done();
        });
      });
      */

      it('should return profile after successfull authentication', (done) => {
        auth0.login({
          connection: 'tests',
          username: 'johnfoo@gmail.com',
          password: '12345',
          sso: false
        }).then(({profile, auth: {id_token, access_token}}) => {
          expect(profile.name).to.eql('John Foo');
          expect(profile.foo).to.eql('bar');
          expect(profile.identities.length).to.eql(1);
          expect(id_token).to.exist;
          expect(access_token).to.exist;
          done();
        }, failPromise(done));
      });

      it('should return refresh_token after successfull authentication with offline_mode', (done) => {
        auth0.login({
          connection: 'tests',
          username: 'johnfoo+1@gmail.com',
          password: '12345',
          // offline_mode: true,
          scope: 'openid offline_access',
          sso: false,
        }).then(({profile, auth: {id_token, access_token, refresh_token}}) => {
          expect(profile.name).to.eql('John Foo');
          expect(profile.foo).to.eql('bar');
          expect(profile.identities.length).to.eql(1);
          expect(id_token).to.exist;
          expect(refresh_token).to.exist;
          expect(access_token).to.exist;
          done();
        }, failPromise(done));
      });

      it('should trim username before login', (done) => {
        auth0.login({
          connection: 'tests',
          username: '    johnfoo+2@gmail.com     ',
          password: '12345',
          sso: false,
        }).then(({profile, auth: {id_token, access_token}}) => {
          expect(profile.name).to.eql('John Foo');
          expect(profile.foo).to.eql('bar');
          expect(profile.identities.length).to.eql(1);
          expect(id_token).to.exist;
          expect(access_token).to.exist;
          done();
        }, failPromise(done));
      });
    });


    // TODO
    describe.skip('with wsfed', () => {
      it('should call the callback when user/pass is wrong', (done) => {
        auth0.login({
          connection: 'tests',
          username: 'testttt@wrong.com',
          password: '12345',
        }).then(failPromise(done), (err) => {
          expect(err.status).to.equal(401);
          expect(err.details.code).to.equal('invalid_user_password');
          done();
        });
      });

      it('should call the callback with err when the connection doesn\'t exists', (done) => {
        auth0.login({
          connection: 'testsw3eeasdsadsa',
          username: 'testtttt@wrong.com',
          password: '12345',
        }).then(failPromise(done), (err) => {
          expect(err.status).to.equal(404);
          expect(err.message).to.match(/connection not found/ig);
          done();
        });
      });

      it('should render wsfed form after successfull authentication', function (done) {
        auth0._renderAndSubmitWSFedForm = function (options, htmlForm) {
          expect(htmlForm).to.match(/<form/);
          done();
        };

        auth0.login({
          connection: 'tests',
          username: 'johnfoo@gmail.com',
          password: '12345'
        });
      });

    });
  });

  describe('Signup', () => {
    it('should fail when the username is null', (done) => {
      auth0.signup({
        connection: 'tests',
        username: null,
        password: '12345'
      }).then(failPromise(done), (err) => {
        expect(err.status).to.equal(400);
        expect(err.message).to.exist;
        expect(err.details).to.exist;
        done();
      });
    });

    it('should handle server errors', (done) => {
      auth0.signup({
        connection: 'tests',
        username:   'pepo@example.com',
        password:   '12345',
        auto_login: false
      }).then(failPromise(done), (err) => {
        expect(err.status).to.equal(401);
        expect(err.message).to.exist;
        expect(err.details).to.exist;
        done();
      });
    });

    describe('with resource owner authentication', () => {
      it('should return profile after successfull signup', (done) => {
        auth0.signup({
          connection: 'tests',
          username:   'johnfoo@gmail.com',
          password:   '12345',
          sso:        false,
        }).then(({profile, auth: {id_token, access_token}}) => {
          expect(profile.name).to.eql('John Foo');
          expect(profile.identities.length).to.eql(1);
          expect(id_token).to.exist;
          expect(access_token).to.exist;
          done();
        }, failPromise(done));
      });

      it('should not return profile after successfull signup if auto_login is false', (done) => {
        auth0._renderAndSubmitWSFedForm = function () {
          done(new Error('this should not be called'));
        };

        auth0.signup({
          connection: 'tests',
          username:   'johnfoo@gmail.com',
          password:   '12345',
          auto_login: false,
          sso: false
        }).then(({profile}) => done(profile), failPromise(done));
      });

      it('should trim username before signup', (done) => {
        auth0.signup({
          connection: 'tests',
          username:   'johnfoo@gmail.com',
          password:   '12345',
          sso:        false
        }).then((profile) => {
          expect(profile).to.be.ok;
          done();
        }, failPromise(done));
      });

      it('should handle username and email when requires_username enabled', (done) => {
        var username = makeUsername(15);

        auth0.signup({
          connection: 'requires-username',
          username:   username,
          email: username + '@gmail.com',
          password:   '12345',
          sso: false
        }).then(({profile}) => {
          expect(profile).to.have.property('username');
          expect(profile).to.have.property('email');
          expect(profile.username).to.equal(username);
          expect(profile.email).to.equal(username + '@gmail.com');
          done();
        }, failPromise(done));
      });

    });


    // TODO
    describe.skip('with wsfed authentication', function () {

      it('should render wsfed form after successfull signup', function (done) {
        auth0._renderAndSubmitWSFedForm = function (options, htmlForm) {
          expect(htmlForm).to.match(/<form/);
          done();
        };

        auth0.signup({
          connection: 'tests',
          username: 'johnfoo@gmail.com',
          password: '12345'
        }, function (err) {
          done(err);
        });
      });

      it('should not render wsfed form after successfull signup if auto_login is false', function (done) {
        auth0._renderAndSubmitWSFedForm = function (options, htmlForm) {
          done(new Error('this should not be called'));
        };

        auth0.signup({
          connection: 'tests',
          username:   'johnfoo@gmail.com',
          password:   '12345',
          auto_login: false
        }, function (err) {
          done(err);
        });
      });

    });

    it('should error when username is missing when requires_username enabled', (done) => {
      var username = makeUsername(15);

      auth0.signup({
        connection: 'requires-username',
        email: username + '@gmail.com',
        password:   '12345'
      }).then(failPromise(done), (err) => {
        expect(err.status).to.equal(400);
        expect(err).to.have.property('message');
        expect(err).to.have.property('details');
        expect(err.message).to.match(/missing username/ig);
        done();
      });
    });
  });

  describe('Change Password', function () {
    // TODO: add a test to check that the user can provide a username or email, when `requires_username` is enabled

    it('should fail when the username is null', (done) => {
      auth0.changePassword({
        connection: 'tests',
        username:   null,
        password:   '12345'
      }).then(failPromise(done), (err) => {
        expect(err.status).to.equal(400);
        expect(err).to.have.property('message');
        expect(err).to.have.property('details');
        done();
      });
    });

    //this timeout sometimes. I need to improve.
    it('should return OK after successfull operation', (done) => {
      auth0.changePassword({
        connection: 'tests',
        username:   'johnfoo@contoso.com',
        password:   '12345'
      }).then(() => done(), failPromise(done));
    });

    it('should trim username before operation', (done) => {
      auth0.changePassword({
        connection: 'tests',
        username:     '    johnfoo@gmail.com    ',
        password:   '12345'
      }).then(() => done(), failPromise(done));
    });

    // TODO does not work on node.
    it.skip('should present a proper error message for password strength errors (xhr ' + xhrSupportPrefix + ' supported)', (done) => {
      // TODO test JSONP request
      if (!xhrSupport) return done();

      var server = sinon.fakeServer.create();

      var response = {
        'name': 'PasswordStrengthError',
        'code': 'invalid_password',
        'description': {
          'rules': [{
            'message': 'At least %d characters in length',
            'format': [6],
            'code': 'lengthAtLeast',
            'verified': false
          }],
          'verified': false
        },
        'statusCode':400
      };

      server.respondWith('POST', 'https://' + auth0._domain + '/dbconnections/change_password',[
        400,
        {'Content-Type': 'application/json'},
        JSON.stringify(response)
      ]);

      auth0.changePassword({
        connection: 'tests',
        username:   'johnfoo@contoso.com',
        password:   '12345'
      }).then(failPromise(done), (err) => {
        expect(err).to.not.be(null);
        expect(err.message).to.eql('Password is not strong enough.');
        expect(err.details).to.eql(response);
        done();
      });

      server.respond();
      server.restore();
    })
  });

  describe('Validate User', () => {
    it('should return "true" if the credentials are valid', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     'johnfoo@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(true);
        done();
      }, failPromise(done));
    });

    it('should return "true" if the credentials with username and email are valid', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     'johnfoo',
        email:        'johnfoo@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(false);
        done();
      }, failPromise(done));
    });

    it('should return "false" if username is invalid', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     'invalid-user@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(false);
        done();
      }, failPromise(done));
    });

    it('should return "false" if email is valid and username is invalid', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     'invalid-user',
        email:        'johnfoo@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(false);
        done();
      }, failPromise(done));
    });

    it('should return "false" if email is invalid and username is valid', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     'johnfoo',
        email:        'invalid#email@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(false);
        done();
      }, failPromise(done));
    });

    it('should return "false" if connection is invalid', (done) => {
      auth0.validateUser({
        connection:   'invalid-conn',
        username:     'johnfoo@gmail.com',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(false);
        done();
      }, failPromise(done));
    });

    it('should return error if connection is not specified', (done) => {
      auth0.validateUser({
        username:     'johnfoo@gmail.com',
        password:     '12345'
      }).then(failPromise(done), (err) => {
        expect(err.message).to.equal('connection parameter is mandatory');
        done();
      });
    });

    it('should trim username before validation', (done) => {
      auth0.validateUser({
        connection:   'tests',
        username:     '    johnfoo@gmail.com    ',
        password:     '12345'
      }).then((valid) => {
        expect(valid).to.equal(true);
        done();
      }, failPromise(done));
    });
  });

});


function makeUsername(size) {
  var uname = '';
  var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  for( var i=0; i < size; i++ ) {
    uname += possible.charAt(Math.floor(Math.random() * possible.length));
  }

  return uname.toLowerCase();
}
