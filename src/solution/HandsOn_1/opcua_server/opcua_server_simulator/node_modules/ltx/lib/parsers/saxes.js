'use strict';

var events = require('events');
var saxes = require('saxes');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var saxes__default = /*#__PURE__*/_interopDefaultLegacy(saxes);

class SaxSaxesjs extends events.EventEmitter {
  constructor() {
    super();
    this.parser = new saxes__default['default'].SaxesParser({ fragment: true });

    this.parser.on("opentag", (a) => {
      this.emit("startElement", a.name, a.attributes);
    });
    this.parser.on("closetag", (el) => {
      this.emit("endElement", el.name);
    });
    this.parser.on("text", (str) => {
      this.emit("text", str);
    });
    this.parser.on("end", () => {
      this.emit("end");
    });
    this.parser.on("error", (e) => {
      this.emit("error", e);
    });
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

module.exports = SaxSaxesjs;
