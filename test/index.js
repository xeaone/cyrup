import Cyrup from '../modules/cyrup.js';

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
