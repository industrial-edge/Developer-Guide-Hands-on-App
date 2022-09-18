'use strict';

var events = require('events');
var xml = require('node-xml');
var _escape = require('../escape.js');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var xml__default = /*#__PURE__*/_interopDefaultLegacy(xml);

/**
 * This cannot be used as long as node-xml starts parsing only after
 * setTimeout(f, 0)
 */
class SaxNodeXML extends events.EventEmitter {
  constructor() {
    super();
    this.parser = new xml__default['default'].SaxParser((handler) => {
      handler.onStartElementNS((elem, attrs, prefix, uri, namespaces) => {
        let i;
        const attrsHash = {};
        if (prefix) {
          elem = prefix + ":" + elem;
        }
        for (i = 0; i < attrs.length; i++) {
          const attr = attrs[i];
          attrsHash[attr[0]] = _escape.unescapeXML(attr[1]);
        }
        for (i = 0; i < namespaces.length; i++) {
          const namespace = namespaces[i];
          const k = !namespace[0] ? "xmlns" : "xmlns:" + namespace[0];
          attrsHash[k] = _escape.unescapeXML(namespace[1]);
        }
        this.emit("startElement", elem, attrsHash);
      });
      handler.onEndElementNS((elem, prefix) => {
        if (prefix) {
          elem = prefix + ":" + elem;
        }
        this.emit("endElement", elem);
      });
      handler.onCharacters((str) => {
        this.emit("text", str);
      });
      handler.onCdata((str) => {
        this.emit("text", str);
      });
      handler.onError((e) => {
        this.emit("error", e);
      });
      // TODO: other events, esp. entityDecl (billion laughs!)
    });
  }

  write(data) {
    this.parser.parseString(data);
  }

  end(data) {
    if (data) {
      this.write(data);
    }
  }
}

module.exports = SaxNodeXML;
