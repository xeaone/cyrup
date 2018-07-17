import Cyrup from './cyrup.js';

Promise.resolve().then(function () {
	return Cyrup.encrypt('password', 'hello world');
}).then(function (data) {
	console.log(data);
	return Cyrup.decrypt('password', data);
}).then(function (data) {
	console.log(data);
}).catch(function (error) {
	console.error(error);
});

// Promise.resolve().then(function () {
// 	return Cyrup.hasher('hello world');
// }).then(function (data) {
// 	console.log(data);
// }).catch(function (error) {
// 	console.error(error);
// });

Promise.resolve().then(function () {
	return Cyrup.stringToBuffer('secret');
}).then(function (password) {
	console.log(password);
	let salt = window.crypto.getRandomValues(new Uint8Array(self.SALT_LENGTH));
	return Cyrup.generateKey(password, salt);
}).then(function (data) {
	console.log(data);
}).catch(function (error) {
	console.error(error);
});
