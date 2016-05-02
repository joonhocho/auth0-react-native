export const failPromise = (done, msg) => (err) => {
  err = err || new Error(msg || 'Should not be here.');
  console.error(err);
  done(err);
};
