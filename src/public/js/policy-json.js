/* Preserve numeric source literals in definitions, including large integer IDs. */
(() => {
  'use strict';
  function parse(source) {
    return JSON.parse(source, (key, value, context) => {
      if (typeof value !== 'number') return value;
      if (context?.source && typeof JSON.rawJSON === 'function') return JSON.rawJSON(context.source);
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
        throw new Error('This browser cannot safely edit these JSON numbers. Use a browser supporting JSON source text access.');
      }
      return value;
    });
  }
  function response(source) {
    const result = JSON.parse(source);
    if (result.definition) result.definition = parse(source).definition;
    return result;
  }
  globalThis.PolicyJSON = { parse, response };
})();
