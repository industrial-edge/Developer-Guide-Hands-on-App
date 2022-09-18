'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var parse = require('./parse.js');
var Parser = require('./Parser.js');
var _escape = require('./escape.js');
var Element = require('./Element.js');
var equal = require('./equal.js');
var createElement = require('./createElement.js');
var tag = require('./tag.js');
var tagString = require('./tagString.js');
var is = require('./is.js');
var clone = require('./clone.js');
var stringify = require('./stringify.js');
var JSONify = require('./JSONify.js');



exports.parse = parse;
exports.Parser = Parser;
exports.escapeXML = _escape.escapeXML;
exports.escapeXMLText = _escape.escapeXMLText;
exports.unescapeXML = _escape.unescapeXML;
exports.unescapeXMLText = _escape.unescapeXMLText;
exports.Element = Element;
exports.attrsEqual = equal.attrsEqual;
exports.childrenEqual = equal.childrenEqual;
exports.equal = equal['default'];
exports.nameEqual = equal.nameEqual;
exports.createElement = createElement;
exports.tag = tag;
exports.tagString = tagString;
exports.isElement = is.isElement;
exports.isNode = is.isNode;
exports.isText = is.isText;
exports.clone = clone;
exports.stringify = stringify;
exports.JSONify = JSONify;
