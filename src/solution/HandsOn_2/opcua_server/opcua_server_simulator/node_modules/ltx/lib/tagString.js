'use strict';

var _escape = require('./escape.js');

function tagString(literals, ...substitutions) {
  let str = "";

  for (let i = 0; i < substitutions.length; i++) {
    str += literals[i];
    str += _escape.escapeXML(substitutions[i]);
  }
  str += literals[literals.length - 1];

  return str;
}

module.exports = tagString;
