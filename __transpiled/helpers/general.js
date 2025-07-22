'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

require('source-map-support/register');
var _ = require('lodash');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var ___default = /*#__PURE__*/_interopDefaultLegacy(_);

function camelCase(string) {
  return ___default["default"].camelCase(string);
}
function pascalCase(string) {
  string = ___default["default"].camelCase(string);
  return string.charAt(0).toUpperCase() + string.slice(1);
}
function kebabCase(string) {
  return ___default["default"].kebabCase(string);
}
function snakeCase(string) {
  return ___default["default"].snakeCase(string);
}
function capitalize(string) {
  return ___default["default"].capitalize(string);
}
function oneLine(string) {
  return string.replace(/\n/g, ' ').trim();
}
function upperCase(string) {
  return ___default["default"].upperCase(string);
}
function lowerCase(string) {
  return ___default["default"].lowerCase(string);
}

exports.camelCase = camelCase;
exports.capitalize = capitalize;
exports.kebabCase = kebabCase;
exports.lowerCase = lowerCase;
exports.oneLine = oneLine;
exports.pascalCase = pascalCase;
exports.snakeCase = snakeCase;
exports.upperCase = upperCase;
//# sourceMappingURL=general.js.map
