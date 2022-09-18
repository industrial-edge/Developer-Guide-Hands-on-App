'use strict';

var ltx = require('./parsers/ltx.js');
var nodeExpat = require('./parsers/node-expat.js');
var nodeXml = require('./parsers/node-xml.js');
var saxJs = require('./parsers/sax-js.js');
var saxes = require('./parsers/saxes.js');

// import libxmljs from "./parsers/libxmljs.js";

var parsers = [
  // libxmljs,
  ltx,
  nodeExpat,
  nodeXml,
  saxJs,
  saxes,
];

module.exports = parsers;
