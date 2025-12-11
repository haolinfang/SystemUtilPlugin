var exec = require('cordova/exec');

exports.putIn = function (arg0, success, error) {
    exec(success, error, 'SystemUtilPlugin', 'putIn', arg0);
};

exports.putOut = function (arg0, success, error) {
    exec(success, error, 'SystemUtilPlugin', 'putOut', arg0);
};