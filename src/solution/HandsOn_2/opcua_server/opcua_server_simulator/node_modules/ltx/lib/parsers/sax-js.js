'use strict';

var events = require('events');
var sax = require('sax');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var sax__default = /*#__PURE__*/_interopDefaultLegacy(sax);

class SaxSaxjs extends events.EventEmitter {
  constructor() {
    super();
    this.parser = sax__default['default'].parser(true);

    this.parser.onopentag = (a) => {
      this.emit("startElement", a.name, a.attributes);
    };
    this.parser.onclosetag = (name) => {
      this.emit("endElement", name);
    };
    this.parser.ontext = (str) => {
      this.emit("text", str);
    };
    this.parser.onend = () => {
      this.emit("end");
    };
    this.parser.onerror = (e) => {
      this.emit("error", e);
    };
  }

  write(data) {
    if (typeof data !== "string") {
      data = data.toString();
    }
    this.parser.write(data);
  }

  end(data) {
    if (data) {
      this.parser.write(data);
    }
    this.parser.close();
  }
}

module.exports = SaxSaxjs;
