/**
 * Create a `LoginError` by extend of `Error`
 *
 * @param {Number} status Http status
 * @param {String} details Error details
 */
export default class LoginError extends Error {
  constructor(status, details) {
    let obj;
    if (typeof details === 'string') {
      try {
        obj = JSON.parse(details);
      } catch (er) {
        obj = {message: details};
      }
    } else {
      obj = details || {description: 'server error'};
    }

    if (!obj.code) obj.code = obj.error;

    if (obj.code === 'unauthorized') status = 401;

    let message;
    if (obj.name === 'PasswordStrengthError') {
      message = 'Password is not strong enough.';
    } else {
      message = obj.description || obj.message || obj.error;
    }

    super(message);

    this.message = message;
    this.status = status;
    this.name = obj.code;
    this.code = obj.code;
    this.details = obj;

    if (status === 0) {
      if (!this.code || this.code !== 'offline') {
        this.code = 'Unknown';
        this.message = 'Unknown error.';
      }
    }
  }
}
