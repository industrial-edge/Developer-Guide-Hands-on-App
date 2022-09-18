'use strict';

function JSONify(el) {
  if (typeof el !== "object") return el;
  return {
    name: el.name,
    attrs: el.attrs,
    children: el.children.map(JSONify),
  };
}

module.exports = JSONify;
