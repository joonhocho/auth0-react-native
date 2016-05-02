import {expect} from 'chai';
import fetch from 'node-fetch';
global.fetch = fetch;
import Auth0 from '../lib';
import sinon from 'sinon';
import {failPromise} from './util';

/**
 * XHR support variables
 */

var xhrSupport = !(new Auth0({clientID: "clientID", domain: "domain"}))._useJSONP;
var xhrSupportPrefix = xhrSupport ? '' : 'not ';

// TODO: we are using the support variables to test only for XHR requests, since
// we don't have an easy way to test JSONP. The plan is to wrap calls to reqwest
// and jsonp so we can stub them.

/**
 * Test User and Password
 */

describe.skip('Auth0 - Passwordless', function () {
  this.timeout(5000);

  let domain;
  let clientID;
  let auth0;
  let server;
  let email;
  let phoneNumber;
  let fetchSaved;
  let response;
  let error;
  let fetchUrl;
  let fetchOptions;
  beforeEach(function () {
    domain = 'aaa.auth0.com';
    clientID = 'aaaabcdefgh';
    auth0 = new Auth0({
      domain,
      clientID,
    });
    server = sinon.fakeServer.create();
    email = 'foo@bar.com';
    phoneNumber = '+5491122334455';
    fetchSaved = global.fetch;
    global.fetch = (url, options) => new Promise((resolve, reject) => {
      fetchUrl = url;
      fetchOptions = options;
      if (response) resolve(response);
      else if (error) reject(error);
    });
  });

  afterEach(function () {
    server.restore();
    fetchUrl = null;
    fetchOptions = null;
    fetchSaved = global.fetch;
    response = null;
    error = null;
  });

  describe('.startPasswordless()', function () {
    it('should throw if no arguments are passed', function () {
      expect(function () {
        auth0.startPasswordless();
      }).to.throwError('An options object is required');
    });

    it('should throw if no options are passed', function () {
      expect(function () {
        auth0.startPasswordless(undefined);
      }).to.throwError('An options object is required');
    });

    it('should throw if options has no property email or phoneNumber', function () {
      expect(function () {
        auth0.startPasswordless({});
      }).to.throwError('email is required.');
    });

    describe('sending an email successfully (xhr ' + xhrSupportPrefix + ' supported)', function() {
      beforeEach(function() {
        response = {
          status: 200,
          json: () => Promise.resolve({
            _id: '5b7bb4',
            email,
          }),
        };
        /*
        server.respondWith('POST', 'https://' + domain + '/passwordless/start', [
          200,
          { 'Content-Type': 'application/json' },
          '{"_id":"5b7bb4","email":"' + email + '"}'
        ]);
        */
      });

      it('should send the expected parameters', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();
        auth0.startPasswordless({ email: email })
          .then(() => {
            expect(fetchUrl).to.equal('https://' + domain + '/passwordless/start');
            expect(fetchOptions.method).to.equal('POST');
            const data = JSON.parse(fetchOptions.body);
            expect(data.client_id).to.equal(clientID);
            expect(data.email).to.equal(email);
            expect(data.connection).to.equal('email');
            done();
          }, failPromise(done));
      });

      it('should allow a send option', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();
        var send = 'code';

        auth0.startPasswordless({ email: email, send: send })
          .then(() => {
            expect(fetchUrl).to.equal('https://' + domain + '/passwordless/start');
            expect(fetchOptions.method).to.equal('POST');
            const data = JSON.parse(fetchOptions.body);
            expect(data.client_id).to.equal(clientID);
            expect(data.email).to.equal(email);
            expect(data.connection).to.equal('email');
            expect(data.send).to.equal(send);
            done();
          }, failPromise(done));
      });

      it('should allow an authParams option', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();
        var authParams = {key: 'fakeauthparams'};

        auth0.startPasswordless({ email: email, authParams: authParams })
          .then(() => {
            expect(fetchUrl).to.equal('https://' + domain + '/passwordless/start');
            expect(fetchOptions.method).to.equal('POST');
            const data = JSON.parse(fetchOptions.body);
            expect(data.client_id).to.equal(clientID);
            expect(data.email).to.equal(email);
            expect(data.connection).to.equal('email');
            expect(data.authParams.key).to.eql(authParams.key);
            done();
          }, failPromise(done));
      });
    });

    describe('unsuccessful attempt to send an email (xhr ' + xhrSupportPrefix + ' supported)', function() {
      beforeEach(function() {
        email = "foo";
        server.respondWith('POST', 'https://' + domain + '/passwordless/start', [
          400,
          { 'Content-Type': 'application/json' },
          '{"error":"bad.email","error_description":"error in email - email format validation failed: ' + email + '"}'
        ]);
      });

      it('should provide the error information', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();

        var email = email;
        auth0.startPasswordless({ email: email }, function (err) {
          expect(err).not.to.be(null);
          expect(err).to.have.property('error');
          expect(err).to.have.property('error_description');
          expect(err.error).to.be('bad.email');
          expect(err.error_description).to.be('error in email - email format validation failed: ' + email);
          done();
        });

        server.respond();
      });
    });

    describe('sending a sms successfully (xhr ' + xhrSupportPrefix + ' supported)', function() {
      beforeEach(function() {
        server.respondWith('POST', 'https://' + domain + '/passwordless/start', [
          200,
          { 'Content-Type': 'application/json' },
          '{}'
        ]);
      });

      it('should send the expected parameters', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();

        auth0.startPasswordless({ phoneNumber: phoneNumber }, function (err) {
          expect(err).to.be(null);
          done();
        });

        var requestData = parseRequestBody(server.requests[0]);
        expect(requestData.client_id).to.be(clientID);
        expect(requestData.phone_number).to.be(phoneNumber);
        expect(requestData.connection).to.be('sms');
        server.respond();
      });

      it('should not allow a send option', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();

        auth0.startPasswordless({ phoneNumber: phoneNumber, send: 'link' }, function (err) {
          done();
        });

        var requestData = parseRequestBody(server.requests[0]);
        expect(requestData.authParams).to.be(undefined);
        server.respond();
      });

      it('should not allow an authParams option', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();

        auth0.startPasswordless({ phoneNumber: phoneNumber, authParams: 'fakeauthparams' }, function (err) {
          done();
        });

        var requestData = parseRequestBody(server.requests[0]);
        expect(requestData.authParams).to.be(undefined);
        server.respond();
      });

    });

    describe('unsuccessful attempt to send a sms (xhr ' + xhrSupportPrefix + ' supported)', function() {
      beforeEach(function() {
        phoneNumber = '+541234';
        server.respondWith('POST', 'https://' + domain + '/passwordless/start', [
          400,
          { 'Content-Type': 'application/json' },
          '{"statusCode":400,"error":"Bad Request","message":"The \'To\' number ' + phoneNumber + ' is not a valid phone number."}'
        ]);
      });

      it('should provide the error information', function (done) {
        // TODO test JSONP request
        if (!xhrSupport) return done();

        auth0.startPasswordless({ phoneNumber: phoneNumber }, function (err) {
          expect(err).not.to.be(null);
          expect(err).to.have.property('statusCode');
          expect(err).to.have.property('error');
          expect(err).to.have.property('message');
          expect(err.statusCode).to.be(400);
          expect(err.error).to.be('Bad Request');
          expect(err.message).to.be('The \'To\' number +541234 is not a valid phone number.');
          done();
        });

        server.respond();
      });
    });
  });

  describe('.loginWithPasscode()', function () {
    it('should throw if called with just a passcode attribute', function (done) {
      expect(function () {
        auth0.loginWithPasscode({ passcode: '123123' }, function () {});
      }).to.throwError(function (err) {
        expect(err.message).to.contain('email');
        expect(err.message).to.contain('phoneNumber');
        done();
      });
    });

    it('should throw if called with just phoneNumber', function (done) {
      expect(function () {
        auth0.loginWithPasscode({ phoneNumber: '+123123123123' }, function () {});
      }).to.throwError(function (err) {
        expect(err.message).to.contain('passcode');
        done();
      });
    });

    it('should throw if called with just email', function (done) {
      expect(function () {
        auth0.loginWithPasscode({ email: 'foo@bar.com' }, function () {});
      }).to.throwError(function (err) {
        expect(err.message).to.contain('passcode');
        done();
      });
    });

    it('should fallback calling .loginWithResourceOwner() with correct options', function (done) {
      auth0.loginWithResourceOwner = function (options, callback) {
        expect(options.sso).to.be(false);
        expect(options.phoneNumber).to.be(undefined);
        expect(options.passcode).to.be(undefined);
        expect(options.username).not.to.be.empty();
        expect(options.password).not.to.be.empty();
        expect(options.connection).to.be('sms');
        expect(options.customOption).to.be('customOption');
        expect(callback).to.be.a('function');
        done();
      }

      auth0.loginWithPhoneNumber({
        phoneNumber: '+123123',
        passcode: '123123',
        connection: 'email',
        customOption: 'customOption'
      }, function () {});
    })
  });

  describe('.login()', function() {
    describe('/oauth/ro', function() {
      describe('successful login (xhr ' + xhrSupportPrefix + ' supported)', function() {
        beforeEach(function() {
          passcode = '123456';
          server.respondWith('POST', 'https://' + domain + '/oauth/ro', [
            200,
            { 'Content-Type': 'application/json' },
            '{}'
          ]);
          // XXX Avoid fetching the profile
          auth0.getProfile = function(id_token, callback) {
            return callback(null, {});
          }
        });

        it('should send the expected parameters', function (done) {
          // TODO test JSONP request
          if (!xhrSupport) return done();

          auth0.login({ phoneNumber: phoneNumber, passcode: passcode }, function (err, profile) {
            expect(err).to.be(null);
            done();
          });

          var requestData = parseRequestBody(server.requests[0]);
          expect(requestData.client_id).to.be(clientID);
          expect(requestData.connection).to.be('sms');
          expect(requestData.grant_type).to.be('password');
          expect(requestData.username).to.be(phoneNumber);
          expect(requestData.password).to.be(passcode);
          expect(requestData.scope).to.be('openid');
          expect(requestData.sso).to.be('false');
          expect(requestData.phoneNumber).to.be(undefined);
          expect(requestData.passcode).to.be(undefined);

          server.respond();
        });
      });
    });
  });
});

function parseRequestBody(request) {
  var result = {};
  if (!request || 'string' !== typeof request.requestBody) {
    return result;
  }

  var pairs = request.requestBody.split('&');
  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i].split('=');
    result[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
  }

  return result;
}
