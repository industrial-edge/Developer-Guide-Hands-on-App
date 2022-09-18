'use strict';

var _escape = require('./escape.js');

function stringify(el, indent, level) {
  if (typeof indent === "number") indent = " ".repeat(indent);
  if (!level) level = 1;
  let s = `<${el.name}`;

  for (const k in el.attrs) {
    const v = el.attrs[k];
    // === null || undefined
    if (v != null) {
      s += ` ${k}="${_escape.escapeXML(typeof v === "string" ? v : v.toString(10))}"`;
    }
  }

  if (el.children.length > 0) {
    s += ">";
    for (const child of el.children) {
      if (child == null) continue;
      if (indent) s += "\n" + indent.repeat(level);
      s +=
        typeof child === "string"
          ? _escape.escapeXMLText(child)
          : stringify(child, indent, level + 1);
    }
    if (indent) s += "\n" + indent.repeat(level - 1);
    s += `</${el.name}>`;
  } else {
    s += "/>";
  }

  return s;
}

module.exports = stringify;
