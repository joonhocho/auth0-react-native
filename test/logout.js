import {expect} from 'chai';
import fetch from 'node-fetch';
global.fetch = fetch;
import Auth0 from '../lib';
import {failPromise} from './util';

/**
 * Test Logout
 */

describe('logout', function() {
  this.timeout(5000);

  it('should redirect to the logout url', (done) => {
    const auth0 = new Auth0({
      domain: 'mdocs.auth0.com',
      callbackURL: 'http://localhost:3000/',
      clientID: 'ptR6URmXef0OfBDHK0aCIy7iPKpdCG4t',
    });

    auth0._redirect = (url) => {
      expect(url).to.equal('https://mdocs.auth0.com/logout');
      done();
    };

    auth0.logout();
  });

  it('should redirect to the logout url with params', (done) => {
    const auth0 = new Auth0({
      domain: 'mdocs.auth0.com',
      callbackURL: 'http://localhost:3000/',
      clientID: 'ptR6URmXef0OfBDHK0aCIy7iPKpdCG4t',
    });

    auth0._redirect = (url) => {
      expect(url).to.equal('https://mdocs.auth0.com/logout?returnTo=http%3A%2F%2Flogout');
      done();
    };

    auth0.logout({returnTo: 'http://logout'});
  });
});
