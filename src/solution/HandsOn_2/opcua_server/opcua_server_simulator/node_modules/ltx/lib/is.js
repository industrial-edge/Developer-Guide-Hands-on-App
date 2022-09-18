'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var Element = require('./Element.js');

function isNode(el) {
  return el instanceof Element || typeof el === "string";
}

function isElement(el) {
  return el instanceof Element;
}

function isText(el) {
  return typeof el === "string";
}

exports.isElement = isElement;
exports.isNode = isNode;
exports.isText = isText;
