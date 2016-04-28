import {expect} from 'chai';
import {
  decodeToken,
  getTokenExpirationDate,
  isTokenExpired,
} from '../lib';

describe('jwt', () => {
  describe('no expiration tokens', () => {
    const infiniteToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts';
    it('should correctly decode it', () => {
      const token = decodeToken(infiniteToken);

      expect(token.name).to.equal('John Doe');
    });

    const multipleUrlCharactersToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZWxsbO-jv2xsbO-jvyIsImFkbWluIjp0cnVlfQ.NCPM3vNwuvJGMIjR0csEFQDrSLcjm5P7ORumVq4ezmo';
    it('should correctly decode tokens with multiple URL-safe characters', () => {
      const token = decodeToken(multipleUrlCharactersToken);

      expect(token.name).to.equal('John Doellllll');
    });

    it('should return no expiration', () => {
      const date = getTokenExpirationDate(infiniteToken);

      expect(date).not.to.exist;
    });

    it('should return not expired', () => {
      expect(isTokenExpired(infiniteToken)).to.be.false;
    });
  });

  describe('tokens with expiration', () => {
    const expToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6ImZhY2Vib29rfDEwMTU0Mjg3MDI3NTEwMzAyIiwiYXVkIjoiQlVJSlNXOXg2MHNJSEJ3OEtkOUVtQ2JqOGVESUZ4REMiLCJleHAiOjE0MTIyMzQ3MzAsImlhdCI6MTQxMjE5ODczMH0.7M5sAV50fF1-_h9qVbdSgqAnXVF7mz3I6RjS6JiH0H8';
    it('should correctly decode it', () => {
      const token = decodeToken(expToken);

      expect(token.sub).to.equal('facebook|10154287027510302');
    });

    it('should return an expiration', () => {
      const date = getTokenExpirationDate(expToken);

      expect(date).to.eql(new Date(1412234730000));
    });
  });
});
