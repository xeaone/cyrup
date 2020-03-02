/*
    Name: cyrup
    Version: 0.7.4
    License: MPL-2.0
    Author: Alexander Elias
    Email: alex.steven.elias@gmail.com
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/
var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _async = function () {
	try {
		if (isNaN.apply(null, {})) {
			return function (f) {
				return function () {
					try {
						return Promise.resolve(f.apply(this, arguments));
					} catch (e) {
						return Promise.reject(e);
					}
				};
			};
		}
	} catch (e) {}return function (f) {
		// Pre-ES5.1 JavaScript runtimes don't accept array-likes in Function.apply
		return function () {
			var args = [];for (var i = 0; i < arguments.length; i++) {
				args[i] = arguments[i];
			}

			try {
				return Promise.resolve(f.apply(this, args));
			} catch (e) {
				return Promise.reject(e);
			}
		};
	};
}();function _await(value, then, direct) {
	if (direct) {
		return then ? then(value) : value;
	}value = Promise.resolve(value);return then ? value.then(then) : value;
}
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

(function (global, factory) {
	(typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) === 'object' && typeof module !== 'undefined' ? module.exports = factory() : typeof define === 'function' && define.amd ? define('Cyrup', factory) : global.Cyrup = factory();
})(this, function () {
	'use strict';

	var Permission = function () {
		function Permission() {
			var _this = this;

			var permission = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

			_classCallCheck(this, Permission);

			var allows = permission.allows,
			    denies = permission.denies,
			    requires = permission.requires,
			    action = permission.action,
			    resource = permission.resource,
			    behavior = permission.behavior;


			this._edit = true;
			this._action = null;
			this._resource = null;
			this._behavior = null;
			this._allows = [];
			this._denies = [];
			this._requires = {};

			if ('action' in permission) this.action(action);
			if ('resource' in permission) this.resource(resource);
			if ('behavior' in permission) this.behavior(behavior);

			if ('allows' in permission) {
				if (allows instanceof Array === false) throw new Error('permission allows illegal type');
				allows.forEach(function (allow) {
					return _this.allow(allow);
				});
			}

			if ('denies' in permission) {
				if (denies instanceof Array === false) throw new Error('permission denies illegal type');
				denies.forEach(function (deny) {
					return _this.deny(deny);
				});
			}

			if ('requires' in permission) {
				if (requires instanceof Object === false) throw new Error('permission requires illegal type');
				Object.entries(requires).forEach(function (_ref) {
					var _ref2 = _slicedToArray(_ref, 2),
					    name = _ref2[0],
					    value = _ref2[1];

					return _this.require(name, value);
				});
			}
		}

		_createClass(Permission, [{
			key: 'action',
			value: function action(_action2) {

				if (_action2 === undefined) return this._action;
				if (typeof _action2 !== 'string') throw new Error('permission action string required');

				this._action = _action2;

				return this;
			}
		}, {
			key: 'resource',
			value: function resource(_resource2) {

				if (_resource2 === undefined) return this._resource;
				if (typeof _resource2 !== 'string') throw new Error('permission resource string required');

				this._resource = _resource2;

				return this;
			}
		}, {
			key: 'behavior',
			value: function behavior(_behavior) {

				if (_behavior === undefined) return this._behavior;
				if (typeof _behavior !== 'boolean') throw new Error('permission behavior boolean required');this._behavior = _behavior;

				return this;
			}
		}, {
			key: 'allows',
			value: function allows() {
				return Object.freeze(this._allows);
			}
		}, {
			key: 'allow',
			value: function allow(_allow) {

				if (typeof _allow !== 'string') throw new Error('permission allow string required');

				var exists = this._allows.includes(_allow);
				if (exists) throw new Error('permission allow ' + _allow + ' exists');

				this._allows.push(_allow);

				return this;
			}
		}, {
			key: 'denies',
			value: function denies() {
				return Object.freeze(this._deniess);
			}
		}, {
			key: 'deny',
			value: function deny(_deny) {

				if (typeof _deny !== 'string') throw new Error('permission deny string required');

				var exists = this._denies.includes(_deny);
				if (exists) throw new Error('permission deny ' + _deny + ' exists');

				this._denies.push(_deny);

				return this;
			}
		}, {
			key: 'requires',
			value: function requires() {
				return Object.freeze(this._requires);
			}
		}, {
			key: 'require',
			value: function require(name, value) {

				if (typeof name !== 'string') throw new Error('permission name string required');
				if (typeof value !== 'string') throw new Error('permission value string required');

				this._requires[name] = value;

				return this;
			}
		}, {
			key: 'edit',
			value: function edit(_edit) {

				if (_edit === undefined) return this._edit;
				if (typeof _edit !== 'boolean') throw new Error('permission edit boolean required');

				this._edit = _edit;

				return this;
			}
		}, {
			key: 'traverse',
			value: function traverse(name, data) {
				var keys = name.split('.');
				var last = keys.pop();
				keys.forEach(function (key) {
					return data = data[key];
				});
				return [last, data];
			}
		}, {
			key: 'validate',
			value: function validate(resource, action, data) {

				if ((typeof data === 'undefined' ? 'undefined' : _typeof(data)) !== 'object') return false;
				if (typeof action !== 'string') return false;
				if (typeof resource !== 'string') return false;

				if (this._action !== action) return false;
				if (this._resource !== resource) return false;

				for (var name in this._requires) {
					var _traverse = this.traverse(name, data),
					    _traverse2 = _slicedToArray(_traverse, 2),
					    key = _traverse2[0],
					    reference = _traverse2[1];

					if (key in reference) {
						if (this._requires[key] === reference[key]) {
							continue;
						} else {
							return false;
						}
					} else {
						return false;
					}
				}

				if (this._behavior) {
					var _iteratorNormalCompletion = true;
					var _didIteratorError = false;
					var _iteratorError = undefined;

					try {
						for (var _iterator = this._denies[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
							var _name = _step.value;

							var _traverse3 = this.traverse(_name, data),
							    _traverse4 = _slicedToArray(_traverse3, 2),
							    _key = _traverse4[0],
							    _reference = _traverse4[1];

							if (_key in _reference) {
								return false;
							} else {
								continue;
							}
						}
					} catch (err) {
						_didIteratorError = true;
						_iteratorError = err;
					} finally {
						try {
							if (!_iteratorNormalCompletion && _iterator.return) {
								_iterator.return();
							}
						} finally {
							if (_didIteratorError) {
								throw _iteratorError;
							}
						}
					}
				} else {
					var _iteratorNormalCompletion2 = true;
					var _didIteratorError2 = false;
					var _iteratorError2 = undefined;

					try {
						for (var _iterator2 = this._allows[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
							var _name2 = _step2.value;

							var _traverse5 = this.traverse(_name2, data),
							    _traverse6 = _slicedToArray(_traverse5, 2),
							    _key2 = _traverse6[0],
							    _reference2 = _traverse6[1];

							if (_key2 in _reference2) {
								return false;
							} else {
								continue;
							}
						}
					} catch (err) {
						_didIteratorError2 = true;
						_iteratorError2 = err;
					} finally {
						try {
							if (!_iteratorNormalCompletion2 && _iterator2.return) {
								_iterator2.return();
							}
						} finally {
							if (_didIteratorError2) {
								throw _iteratorError2;
							}
						}
					}
				}

				return true;
			}
		}, {
			key: 'valid',
			value: function valid() {

				if (typeof this._action !== 'string') return false;
				if (typeof this._resource !== 'string') return false;
				if (typeof this._behavior !== 'boolean') return false;

				return true;
			}
		}, {
			key: 'toJSON',
			value: function toJSON() {
				return {
					action: this._action,
					resource: this._resource,
					behavior: this._behavior,
					allows: this._allows,
					denies: this._denies,
					requires: this._requires
				};
			}
		}]);

		return Permission;
	}();

	var Role = function () {
		function Role() {
			var _this2 = this;

			var role = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

			_classCallCheck(this, Role);

			var name = role.name,
			    active = role.active,
			    permissions = role.permissions;


			this._edit = true;
			this._name = null;
			this._active = null;
			this._permissions = [];

			if ('name' in role) this.name(name);
			if ('active' in role) this.active(active);

			if ('permissions' in role) {
				if (permissions instanceof Array === false) throw new Error('role permissions illegal type');
				permissions.forEach(function (permission) {
					return _this2.permission(permission);
				});
			}
		}

		_createClass(Role, [{
			key: 'permission',
			value: function permission() {
				var permission = new (Function.prototype.bind.apply(Permission, [null].concat(Array.prototype.slice.call(arguments))))();
				this.add(permission);
				return permission;
			}
		}, {
			key: 'add',
			value: function add(permission) {

				if (permission instanceof Permission === false) throw new Error('role add requires permission');
				// if (permission.valid() === false) throw new Error('role add permission invalid');

				var action = permission.action();
				var resource = permission.resource();

				var exists = this._permissions.find(function (_ref3) {
					var _resource = _ref3._resource,
					    _action = _ref3._action;

					return _resource === resource && _action === action;
				});

				if (exists) throw new Error('role add permission ' + resource + ' ' + action + ' exists');

				this._permissions.push(permission);

				return this;
			}
		}, {
			key: 'name',
			value: function name(_name3) {

				if (_name3 === undefined) return this._name;
				if (typeof _name3 !== 'string') throw new Error('role name string required');

				this._name = _name3;

				return this;
			}
		}, {
			key: 'active',
			value: function active(_active) {

				if (_active === undefined) return this._active;
				if (typeof _active !== 'boolean') throw new Error('role active boolean required');

				this._active = _active;

				return this;
			}
		}, {
			key: 'edit',
			value: function edit(_edit2) {

				if (_edit2 === undefined) return this._edit;
				if (typeof _edit2 !== 'boolean') throw new Error('role edit boolean required');

				this._edit = _edit2;

				return this;
			}
		}, {
			key: 'validate',
			value: function validate(resource, action, data) {

				if ((typeof data === 'undefined' ? 'undefined' : _typeof(data)) !== 'object') return false;
				if (typeof action !== 'string') return false;
				if (typeof resource !== 'string') return false;

				if (this._active === false) return false;

				var permissions = this._permissions;
				var _iteratorNormalCompletion3 = true;
				var _didIteratorError3 = false;
				var _iteratorError3 = undefined;

				try {
					for (var _iterator3 = permissions[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
						var permission = _step3.value;

						if (permission.validate(resource, action, data)) {
							continue;
						} else {
							return false;
						}
					}
				} catch (err) {
					_didIteratorError3 = true;
					_iteratorError3 = err;
				} finally {
					try {
						if (!_iteratorNormalCompletion3 && _iterator3.return) {
							_iterator3.return();
						}
					} finally {
						if (_didIteratorError3) {
							throw _iteratorError3;
						}
					}
				}

				return true;
			}
		}, {
			key: 'valid',
			value: function valid() {

				if (typeof this._name !== 'string') return false;
				if (typeof this._active !== 'boolean') return false;

				var _iteratorNormalCompletion4 = true;
				var _didIteratorError4 = false;
				var _iteratorError4 = undefined;

				try {
					for (var _iterator4 = this._permissions[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
						var permission = _step4.value;

						if (permission.valid() === false) {
							return false;
						}
					}
				} catch (err) {
					_didIteratorError4 = true;
					_iteratorError4 = err;
				} finally {
					try {
						if (!_iteratorNormalCompletion4 && _iterator4.return) {
							_iterator4.return();
						}
					} finally {
						if (_didIteratorError4) {
							throw _iteratorError4;
						}
					}
				}

				return true;
			}
		}, {
			key: 'permissions',
			value: function permissions() {
				return Object.freeze(this._permissions);
			}
		}, {
			key: 'toJSON',
			value: function toJSON() {
				return {
					name: this._name,
					active: this._active,
					permissions: this._permissions
				};
			}
		}]);

		return Role;
	}();

	// {
	//     resource: 'user',
	//     action: 'update',
	//     behavior: true,
	//     requires: {
	//         account: 'ACCOUNT',
	//     },
	//     allows: [
	//         'firstName'
	//     ],
	//     denies: [
	//         'lastName'
	//     ]
	// };

	var Access = function () {
		function Access() {
			var _this3 = this;

			var access = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

			_classCallCheck(this, Access);

			var roles = access.roles;


			this._roles = {};

			if ('roles' in access) {
				if (roles instanceof Array === false) throw new Error('access roles illegal type');
				roles.forEach(function (role) {
					return _this3.role(role);
				});
			}
		}

		_createClass(Access, [{
			key: 'role',
			value: function role() {
				var role = new (Function.prototype.bind.apply(Role, [null].concat(Array.prototype.slice.call(arguments))))();
				this.add(role);
				return role;
			}
		}, {
			key: 'get',
			value: function get(role) {

				if (role instanceof Role === false) throw new Error('access get requires role');

				var name = role.name();

				return this._roles[name];
			}
		}, {
			key: 'add',
			value: function add(role) {

				if (role instanceof Role === false) throw new Error('access add requires role');

				var name = role.name();
				var exists = name in this._roles;
				if (exists) throw new Error('access add role ' + name + ' exists');

				this._roles[name] = role;

				return this;
			}
		}, {
			key: 'remove',
			value: function remove(role) {

				if (role instanceof Role === false) throw new Error('access remove requires role');

				var name = role.name();
				var exists = name in this._roles;
				if (exists) throw new Error('access remove role ' + name + ' exists');

				delete this._roles[name];

				return this;
			}
		}, {
			key: 'roles',
			value: function roles() {
				return Object.freeze(this._roles);
			}
		}, {
			key: 'toJSON',
			value: function toJSON() {
				return this._roles;
			}
		}]);

		return Access;
	}();

	var Cyrup = {

		ENCODING: 'hex',
		ITERATIONS: 999999,

		KEY: 32,
		TAG: 16,
		SALT: 16,
		VECTOR: 12,
		RANDOM: 20,
		HASH: 'sha-512',
		ALGORITHM: 'aes-256-gcm',

		Role: Role,
		Access: Access,
		Permission: Permission,

		role: function role() {
			return new (Function.prototype.bind.apply(Role, [null].concat(Array.prototype.slice.call(arguments))))();
		},
		access: function access() {
			return new (Function.prototype.bind.apply(Access, [null].concat(Array.prototype.slice.call(arguments))))();
		},
		permission: function permission() {
			return new (Function.prototype.bind.apply(Permission, [null].concat(Array.prototype.slice.call(arguments))))();
		},
		random: _async(function (size) {
			var _this4 = this;

			var self = _this4;

			size = size || self.RANDOM;

			return _await(self.randomBytes(size), function (buffer) {
				return _await(self.bufferToHex(buffer));
			});
		}),
		hash: _async(function (item, type) {
			var _this5 = this;

			var self = _this5;

			if (!item) throw new Error('Cyrup.hash - item argument required');

			type = self.normalizeHash(type || self.HASH);

			return _await(self.stringToBuffer(item), function (buffer) {
				return _await(self.createHash(buffer, type), function (bufferHash) {
					return _await(self.bufferToHex(bufferHash));
				});
			});
		}),
		compare: _async(function (password, key) {
			var _this6 = this;

			var self = _this6;

			if (!key) throw new Error('Cyrup.compare - key argument required');
			if (!password) throw new Error('Cyrup.compare - password argument required');

			return _await(self.hexToBuffer(key.split(':')[1]), function (salt) {
				return _await(self.key(password, { salt: salt }), function (data) {

					return data === key;
				});
			});
		}),
		key: _async(function (item, data) {
			var _this7 = this;

			var self = _this7;

			if (!item) throw new Error('Cyrup.key - item argument required');

			data = data || {};
			data.size = data.size || self.KEY;
			data.salt = data.salt || self.SALT;
			data.iterations = data.iterations || self.ITERATIONS;
			data.hash = self.normalizeHash(data.hash || self.HASH);

			return _await(Promise.all([typeof item === 'string' ? self.stringToBuffer(item) : item, typeof data.salt === 'string' ? self.stringToBuffer(data.salt) : typeof data.salt === 'number' ? self.randomBytes(data.salt) : data.salt]), function (_ref4) {
				var _ref5 = _slicedToArray(_ref4, 2),
				    bItem = _ref5[0],
				    bSalt = _ref5[1];

				return _await(self.pbkdf2(bItem, bSalt, data.iterations, data.size, data.hash), function (bKey) {
					return _await(Promise.all([self.bufferToHex(bKey), self.bufferToHex(bSalt)]), function (_ref6) {
						var _ref7 = _slicedToArray(_ref6, 2),
						    hKey = _ref7[0],
						    hSalt = _ref7[1];

						return hKey + ':' + hSalt;
					});
				});
			});
		}),
		encrypt: _async(function (data, key, algorithm, vector) {
			var _this8 = this;

			var self = _this8;

			if (!key) throw new Error('Cyrup.encrypt - key argument required');
			if (!data) throw new Error('Cyrup.encrypt - data argument required');

			key = key.split(':');
			vector = vector || self.VECTOR;
			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			return _await(Promise.all([self.hexToBuffer(key[0]), typeof data === 'string' ? self.stringToBuffer(data) : data, typeof vector === 'string' ? self.stringToBuffer(vector) : self.randomBytes(vector)]), function (_ref8) {
				var _ref9 = _slicedToArray(_ref8, 3),
				    bKey = _ref9[0],
				    bData = _ref9[1],
				    bVector = _ref9[2];

				return _await(self.cipher(algorithm, bKey, bVector, bData), function (bEncrypted) {
					return _await(Promise.all([self.bufferToHex(bEncrypted), self.bufferToHex(bVector)]), function (_ref10) {
						var _ref11 = _slicedToArray(_ref10, 2),
						    hEncrypted = _ref11[0],
						    hVector = _ref11[1];

						return hEncrypted + ':' + hVector;
					});
				});
			});
		}),
		decrypt: _async(function (data, key, algorithm) {
			var _this9 = this;

			var self = _this9;

			if (!key) throw new Error('Cyrup.decrypt - key argument required');
			if (!data) throw new Error('Cyrup.decrypt - data argument required');

			algorithm = self.normalizeAlgorithm(algorithm || self.ALGORITHM);

			key = key.split(':');
			data = data.split(':');

			return _await(Promise.all([self.hexToBuffer(key[0]), self.hexToBuffer(data[0]), self.hexToBuffer(data[1])]), function (_ref12) {
				var _ref13 = _slicedToArray(_ref12, 3),
				    bKey = _ref13[0],
				    bData = _ref13[1],
				    bVector = _ref13[2];

				return _await(self.decipher(algorithm, bKey, bVector, bData), function (bDecrypted) {
					return _await(self.bufferToString(bDecrypted));
				});
			});
		})
	};

	if (typeof window === 'undefined') {

		var Util = require('util');
		var Crypto = require('crypto');
		var Pbkdf2 = Util.promisify(Crypto.pbkdf2);
		var RandomBytes = Util.promisify(Crypto.randomBytes);

		Cyrup.normalizeHash = function (hash) {
			return hash.replace('-', '').toLowerCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			return algorithm.toLowerCase();
		};

		Cyrup.hexToBuffer = _async(function (hex) {
			return Buffer.from(hex, 'hex');
		});

		Cyrup.bufferToHex = _async(function (buffer) {
			return buffer.toString('hex');
		});

		Cyrup.stringToBuffer = _async(function (string) {
			return Buffer.from(string, 'utf8');
		});

		Cyrup.bufferToString = _async(function (buffer) {
			return buffer.toString('utf8');
		});

		Cyrup.createHash = _async(function (buffer, type) {
			return Crypto.createHash(type).update(buffer).digest();
		});

		Cyrup.randomBytes = _async(function (bytes) {
			return RandomBytes(bytes);
		});

		Cyrup.pbkdf2 = _async(function (password, salt, iterations, size, hash) {
			return Pbkdf2(password, salt, iterations, size, hash);
		});

		Cyrup.cipher = _async(function (algorithm, key, vector, data) {
			var cipher = Crypto.createCipheriv(algorithm, key, vector);
			return Buffer.concat([cipher.update(data, 'utf8'), cipher.final(), cipher.getAuthTag()]);
		});

		Cyrup.decipher = _async(function (algorithm, key, vector, data) {
			var _this10 = this;

			var self = _this10;
			var buffer = Buffer.from(data, 'hex');
			var tag = buffer.slice(buffer.byteLength - self.TAG);
			var text = buffer.slice(0, buffer.byteLength - self.TAG);
			var decipher = Crypto.createDecipheriv(algorithm, key, vector);

			decipher.setAuthTag(tag);

			return Buffer.concat([decipher.update(text), decipher.final()]);
		});
	} else {

		Cyrup.normalizeHash = function (hash) {
			return hash.toUpperCase();
		};

		Cyrup.normalizeAlgorithm = function (algorithm) {
			if (algorithm.toLowerCase().indexOf('aes') !== 0) return algorithm;
			var algorithms = algorithm.split('-');
			return (algorithms[0] + '-' + algorithms[2]).toUpperCase();
		};

		Cyrup.getAuthTag = function (encrypted) {
			return encrypted.slice(encrypted.byteLength - this.TAG);
		};

		Cyrup.hexToBuffer = _async(function (hex) {

			if (typeof hex !== 'string') {
				throw new TypeError('Cyrup.hexToBuffer - expected input to be a string');
			}

			if (hex.length % 2 !== 0) {
				throw new RangeError('Cyrup.hexToBuffer - expected string to be an even number of characters');
			}

			var bytes = new Uint8Array(hex.length / 2);

			for (var i = 0, l = hex.length; i < l; i += 2) {
				bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
			}

			return bytes.buffer;
		});

		Cyrup.bufferToHex = _async(function (buffer) {
			var bytes = new Uint8Array(buffer);
			var hex = new Array(bytes.length);

			for (var i = 0, l = bytes.length; i < l; i++) {
				hex[i] = ('00' + bytes[i].toString(16)).slice(-2);
			}

			return hex.join('');
		});

		Cyrup.stringToBuffer = _async(function (string) {
			var bytes = new Uint8Array(string.length);

			for (var i = 0, l = string.length; i < l; i++) {
				bytes[i] = string.charCodeAt(i);
			}

			return bytes.buffer;
		});

		Cyrup.bufferToString = _async(function (buffer) {
			var bytes = new Uint8Array(buffer);
			var string = new Array(bytes.length);

			for (var i = 0, l = bytes.length; i < l; i++) {
				string[i] = String.fromCharCode(bytes[i]);
			}

			return string.join('');
		});

		Cyrup.createHash = _async(function (buffer, type) {
			return window.crypto.subtle.digest(type, buffer);
		});

		Cyrup.randomBytes = _async(function (size) {
			return window.crypto.getRandomValues(new Uint8Array(size));
		});

		Cyrup.pbkdf2 = _async(function (password, salt, iterations, size, hash) {
			return _await(window.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']), function (key) {
				return _await(window.crypto.subtle.deriveBits({
					salt: salt,
					iterations: iterations,
					name: 'PBKDF2',
					hash: { name: hash }
				}, key, size << 3), function (bits) {

					return new Uint8Array(bits);
				});
			});
		});

		Cyrup.cipher = _async(function (algorithm, key, vector, data) {
			var _this11 = this;

			var self = _this11;

			return _await(window.crypto.subtle.importKey('raw', key, {
				name: algorithm
			}, false, ['encrypt']), function (oKey) {
				return _await(window.crypto.subtle.encrypt({
					iv: vector,
					name: algorithm,
					tagLength: self.TAG * 8
				}, oKey, data));
			});
		});

		Cyrup.decipher = _async(function (algorithm, key, vector, data) {
			var _this12 = this;

			var self = _this12;

			return _await(window.crypto.subtle.importKey('raw', key, {
				name: algorithm
			}, false, ['decrypt']), function (oKey) {
				return _await(window.crypto.subtle.decrypt({
					iv: vector,
					name: algorithm,
					tagLength: self.TAG * 8
				}, oKey, data));
			});
		});
	}

	return Cyrup;
});