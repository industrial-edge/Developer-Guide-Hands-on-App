'use strict';

var tagString = require('./tagString.js');
var parse = require('./parse.js');

function tag(...args) {
  return parse(tagString(...args));
}

module.exports = tag;
