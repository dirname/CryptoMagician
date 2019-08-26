const expect = require('chai').expect;
const assert = require('assert');


describe('Library Testing', function() {
    it('Cryptian Testing', function() {
        const {algorithm} = require('cryptian');
        const des = new algorithm.Des();

        des.setKey(Buffer.from('0a0c0e1012141618', 'hex'));

        const ciphertext = Buffer.from('a1502d70ba1320c8', 'hex');
        const plaintext  = Buffer.from('0001020304050607', 'hex');

        assert(ciphertext.equals(des.encrypt(plaintext)), 'encrypted Plain Text should equal to Cipher Text');
        assert(plaintext.equals(des.decrypt(ciphertext)), 'decrypted Cipher Text should equal to Plain Text');

    });


});

var chaiAsPromised = require("chai-as-promised")
    , scrypt = require("scrypt")
    , chai = require("chai");
chai.use(chaiAsPromised);

describe("Scrypt Node Module Tests", function() {
    describe("Scrypt Params Function", function() {
        //Examines a returned Params JSON object
        var examine = function(obj, err) {
            expect(err)
                .to.not.exist;

            expect(obj)
                .to.be.a("Object")
                .and.to.have.all.keys("N","r","p");

            expect(obj)
                .to.have.property("N")
                .and.to.be.a("Number");

            expect(obj)
                .to.have.property("r")
                .and.to.be.a("Number");

            expect(obj)
                .to.have.property("p")
                .and.to.be.a("Number");
        }

        describe("Synchronous functionality with incorrect arguments", function () {
            it("Will throw SyntexError exception if called without arguments", function () {
                expect(scrypt.paramsSync)
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: At least one argument is needed - the maxtime$/);
            });

            it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
                expect(function() { scrypt.paramsSync(-1); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: maxtime must be greater than 0$/);
            });

            it("Will throw a TypeError exception if maxmem is not an integer", function() {
                expect(function() { scrypt.paramsSync(1, 2.4); })
                    .to.throw(TypeError)
                    .to.match(/^TypeError: maxmem must be an integer$/);
            });

            it("Will throw a RangeError exception if maxmem is less than 0", function() {
                expect(function() { scrypt.paramsSync(1, -2); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
            });

            it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
                expect(function() { scrypt.paramsSync(1, 2, -0.1); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);

                expect(function() { scrypt.paramsSync(1, 2, 1.1); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
            });

            it("Will throw a TypeError if any arguments are not numbers", function() {
                var args = [1, 2, 0.9];

                for (var i=0; i < args.length; i++) {
                    var temp = args[i];
                    args[i] = "not a number";
                    expect(function() { scrypt.paramsSync(args[0], args[1], args[2]); })
                        .to.throw(TypeError)
                        .to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);

                    args[i] = temp;
                }
            });
        });

        describe("Synchronous functionality with correct arguments", function() {
            it("Should return a JSON object when only maxtime is defined", function() {
                var params = scrypt.paramsSync(1);
                examine(params);
            });

            it("Should return a JSON object when only maxtime and maxmem are defined", function() {
                var params = scrypt.paramsSync(1, 2);
                examine(params);
            });

            it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function() {
                var params = scrypt.paramsSync(1, 2, 0.5);
                examine(params);
            });
        });

        describe("Asynchronous functionality with incorrect arguments", function() {
            var promise = undefined;

            // Disables promises for async test (if promises are available)
            before(function() {
                if (typeof Promise !== "undefined") {
                    promise = Promise;
                    Promise = undefined;
                }
            });

            // Restores promises
            after(function() {
                if (typeof Promise === "undefined" && promise) {
                    Promise = promise;
                }
            });

            it("Will throw SyntexError exception if called without arguments", function () {
                expect(scrypt.params)
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: No arguments present$/);
            });

            it("Will throw a SyntaxError if no callback function is present", function() {
                expect(function() {scrypt.params(1);})
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
            })

            it("Will throw a SyntaxError if callback function is the first argument present", function() {
                expect(function() {scrypt.params(function(){});})
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: At least one argument is needed before the callback - the maxtime$/);
            })

            it("Will throw a RangeError exception if maxtime argument is less than zero", function() {
                expect(function() { scrypt.params(-1, function(){}); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: maxtime must be greater than 0$/);
            });

            it("Will throw a TypeError exception if maxmem is not an integer", function() {
                expect(function() { scrypt.params(1, 2.4, function(){}); })
                    .to.throw(TypeError)
                    .to.match(/^TypeError: maxmem must be an integer$/);
            });

            it("Will throw a RangeError exception if maxmem is less than 0", function() {
                expect(function() { scrypt.params(1, -2, function(){}); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: maxmem must be greater than or equal to 0$/);
            });

            it("Will throw a RangeError exception if max_memfrac is not between 0.0 and 1.0", function() {
                expect(function() { scrypt.params(1, 2, -0.1, function(){}); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);

                expect(function() { scrypt.params(1, 2, 1.1, function(){}); })
                    .to.throw(RangeError)
                    .to.match(/^RangeError: max_memfrac must be between 0.0 and 1.0 inclusive$/);
            });

            it("Will throw a TypeError if any arguments are not numbers", function() {
                var args = [1, 2, 0.9];

                for (var i=0; i < args.length; i++) {
                    var temp = args[i];
                    args[i] = "not a number";
                    expect(function() { scrypt.params(args[0], args[1], args[2], function(){}); })
                        .to.throw(TypeError)
                        .to.match(/^TypeError: (maxtime|maxmem|max_memfrac) must be a number$/);

                    args[i] = temp;
                }
            });
        });

        describe("Asynchronous functionality with correct arguments", function() {
            it("Should return a JSON object when only maxtime is defined", function(done) {
                scrypt.params(1, function(err, params) {
                    examine(params, err);
                    done();
                });
            });

            it("Should return a JSON object when only maxtime and maxmem are defined", function(done) {
                scrypt.params(1, 2, function(err, params){
                    examine(params, err);
                    done();
                });
            });

            it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function(done) {
                scrypt.params(1, 2, 0.5, function(err, params){
                    examine(params, err);
                    done();
                });
            });
        });

        describe("Promise asynchronous functionality with correct arguments", function() {
            if (typeof Promise !== "undefined") {
                it("Should return a JSON object when only maxtime is defined", function(done){
                    scrypt.params(1).then(function(params) {
                        examine(params);
                        done();
                    });
                });

                it("Should return a JSON object when only maxtime and maxmem are defined", function(done) {
                    scrypt.params(1, 2).then(function(params) {
                        examine(params);
                        done();
                    });
                });

                it("Should return a JSON object when maxtime, maxmem and max_memfrac are defined", function(done) {
                    scrypt.params(1, 2, 0.5).then(function(params) {
                        examine(params);
                        done();
                    });
                });
            }
        });
    });

    describe("Scrypt KDF Function", function() {
        describe("Synchronous functionality with incorrect arguments", function(){
            it("Will throw SyntexError exception if called without arguments", function () {
                expect(scrypt.kdfSync)
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: At least two arguments are needed - the key and the Scrypt paramaters object$/);
            });

            it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                expect(function(){scrypt.kdfSync(1123, {N:1, r:1, p:1})})
                    .to.throw(TypeError)
                    .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
            })

            it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
                expect(function(){scrypt.kdfSync("password", {N:1, p:1})})
                    .to.throw(TypeError)
                    .to.match(/^TypeError: Scrypt params object does not have 'r' property present$/);
            })
        });

        describe("Synchronous functionality with correct arguments", function() {
            it("Will return a buffer object containing the KDF with a string input", function() {
                var result = scrypt.kdfSync("password", {N:1, r:1, p:1});
                expect(result)
                    .to.be.an.instanceof(Buffer);
                expect(result)
                    .to.have.length.above(0);
            });
        });

        describe("Asynchronous functionality with incorrect arguments", function() {
            var promise = undefined;

            // Disables promises for async test (if promises are available)
            before(function() {
                if (typeof Promise !== "undefined") {
                    promise = Promise;
                    Promise = undefined;
                }
            });

            // Restores promises
            after(function() {
                if (typeof Promise === "undefined" && promise) {
                    Promise = promise;
                }
            });

            it("Will throw SyntexError exception if called without arguments", function () {
                expect(scrypt.kdf)
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: No arguments present$/);
            });

            it("Will throw a SyntaxError if no callback function is present", function() {
                expect(function() {scrypt.kdf(new Buffer("password"), {N:1, r:1, p:1});})
                    .to.throw(SyntaxError)
                    .to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
            })

            it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                expect(function(){scrypt.kdf(1123, {N:1, r:1, p:1}, function(){})})
                    .to.throw(TypeError)
                    .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
            })

            it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
                expect(function(){scrypt.kdf("password", {N:1, r:1}, function(){})})
                    .to.throw(TypeError)
                    .to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
            })
        });

        describe("Asynchronous functionality with correct arguments", function() {
            it("Will return a buffer object containing the KDF with a buffer input", function(done) {
                scrypt.kdf(new Buffer("password"), {N:1, r:1, p:1}, function(err, result) {
                    expect(result)
                        .to.be.an.instanceof(Buffer);
                    expect(result)
                        .to.have.length.above(0);
                    expect(err)
                        .to.not.exist;
                    done();
                });
            });
        });

        describe("Promise asynchronous functionality with correct arguments", function() {
            if (typeof Promise !== "undefined") {
                it("Will return a buffer object containing the KDF with a buffer input", function(done) {
                    scrypt.kdf(new Buffer("password"), {N:16, r:1, p:1}).then(function(result) {
                        expect(result)
                            .to.be.an.instanceof(Buffer);
                        expect(result)
                            .to.have.length.above(0);
                        done();
                    });
                });
            }
        });
    });

    describe("Scrypt Hash Function", function() {
        describe("Create Hash", function() {
            describe("Synchronous functionality with incorrect arguments", function() {
                it("Will throw SyntexError exception if called without arguments", function () {
                    expect(scrypt.hashSync)
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: At least four arguments are needed - the key to hash, the scrypt params object, the output length of the hash and the salt$/);
                });

                it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                    expect(function(){scrypt.hashSync(1123, {N:1, r:1, p:1}, 32, "NaCl")})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
                })

                it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
                    expect(function(){scrypt.hashSync("hash something", {N:1, r:1}, 32, "NaCl")})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
                })

                it("Will throw a TypeError if the hash length is not an integer", function() {
                    expect(function(){scrypt.hashSync("hash something", {N:1, r:1, p:1}, 32.5, new Buffer("NaCl"))})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Hash length must be an integer$/);

                    expect(function(){scrypt.hashSync("hash something", {N:1, r:1, p:1}, "thirty-two", "NaCl")})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Hash length must be an integer$/);
                })

                it("Will throw a TypeError if the salt is not a string or a Buffer object", function() {
                    expect(function(){scrypt.hashSync("hash something", {N:1, r:1, p:1}, 32, 45)})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Salt type is incorrect: It can only be of type string or Buffer$/);
                })
            });

            describe("Synchronous functionality with correct arguments", function() {
                var hash_length = Math.floor(Math.random() * 100) + 1; //Choose random number between 1 and 100
                it("Will return a buffer object containing the hash with a string input", function() {
                    var result = scrypt.hashSync("hash something", {N:16, r:1, p:1}, hash_length, "NaCl");
                    expect(result)
                        .to.be.an.instanceof(Buffer);
                    expect(result)
                        .to.have.length(hash_length);
                });
            });

            describe("Asynchronous functionality with incorrect arguments", function() {
                var promise = undefined;

                // Disables promises for async test (if promises are available)
                before(function() {
                    if (typeof Promise !== "undefined") {
                        promise = Promise;
                        Promise = undefined;
                    }
                });

                // Restores promises
                after(function() {
                    if (typeof Promise === "undefined" && promise) {
                        Promise = promise;
                    }
                });

                it("Will throw SyntexError exception if called without arguments", function () {
                    expect(scrypt.hash)
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: No arguments present$/);
                });

                it("Will throw a SyntaxError if no callback function is present", function() {
                    expect(function() {scrypt.hash("hash something", {N:16, r:1, p:1}, 64, "NaCl");})
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
                })

                it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                    expect(function(){scrypt.hash(1123, {N:16, r:1, p:1}, 32, "NaCl", function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
                })

                it("Will throw a TypeError if the Scrypt params object is incorrect", function() {
                    expect(function(){scrypt.hash("hash something", {N:16, r:1}, 32, "NaCl", function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Scrypt params object does not have 'p' property present$/);
                })

                it("Will throw a TypeError if the hash length is not an integer", function() {
                    expect(function(){scrypt.hash("hash something", {N:16, r:1, p:1}, 32.5, new Buffer("NaCl"), function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Hash length must be an integer$/);

                    expect(function(){scrypt.hash("hash something", {N:16, r:1, p:1}, "thirty-two", "NaCl", function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Hash length must be an integer$/);
                })

                it("Will throw a TypeError if the salt is not a string or a Buffer object", function() {
                    expect(function(){scrypt.hash("hash something", {N:16, r:1, p:1}, 32, 45, function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Salt type is incorrect: It can only be of type string or Buffer$/);
                })
            });

            describe("Asynchronous functionality with correct arguments", function() {
                var hash_length = Math.floor(Math.random() * 100) + 1; //Choose random number between 1 and 100
                it("Will return a buffer object containing the hash with a string input", function(done) {
                    scrypt.hash("hash something", {N:16, r:1, p:1}, hash_length, "NaCl", function(err, result){
                        expect(result)
                            .to.be.an.instanceof(Buffer);
                        expect(result)
                            .to.have.length(hash_length);
                        expect(err)
                            .to.not.exist;
                        done();
                    });
                });
            });

            describe("Promise asynchronous functionality with correct arguments", function() {
                if (typeof Promise !== "undefined") {
                    var hash_length = Math.floor(Math.random() * 100) + 1; //Choose random number between 1 and 100
                    it("Will return a buffer object containing the hash with a string input", function(done) {
                        scrypt.hash("hash something", {N:16, r:1, p:1}, hash_length, "NaCl").then(function(result){
                            expect(result)
                                .to.be.an.instanceof(Buffer);
                            expect(result)
                                .to.have.length(hash_length);
                            done();
                        });
                    });
                }
            });
        });

        describe("Verify Hash", function() {
            describe("Synchronous functionality with incorrect arguments", function() {
                it("Will throw SyntexError exception if called without arguments", function () {
                    expect(scrypt.verifyKdfSync)
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: At least two arguments are needed - the KDF and the key$/);
                });

                it("Will throw a TypeError if the KDF is not a string or a Buffer object", function() {
                    expect(function(){scrypt.verifyKdfSync(1232,"key")})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: KDF type is incorrect: It can only be of type string or Buffer$/);
                });

                it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                    expect(function(){scrypt.verifyKdfSync("KDF", 1232)})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
                });
            });

            describe("Synchronous functionality with correct arguments", function() {
                var key = "kdf"
                    , kdf = scrypt.kdfSync(key, {N:16, r:1, p:1});

                it("Will produce a boolean value", function(){
                    expect(scrypt.verifyKdfSync(kdf, key))
                        .to.be.a('boolean');

                    expect(scrypt.verifyKdfSync(kdf, "different key"))
                        .to.be.a('boolean');
                });
            });

            describe("Asynchronous functionality with incorrect arguments", function() {
                var promise = undefined;

                // Disables promises for async test (if promises are available)
                before(function() {
                    if (typeof Promise !== "undefined") {
                        promise = Promise;
                        Promise = undefined;
                    }
                });

                // Restores promises
                after(function() {
                    if (typeof Promise === "undefined" && promise) {
                        Promise = promise;
                    }
                });

                it("Will throw SyntexError exception if called without arguments", function () {
                    expect(scrypt.verifyKdf)
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: No arguments present$/);
                });

                it("Will throw a SyntaxError if no callback function is present", function() {
                    var key = "kdf"
                        , kdf = scrypt.kdfSync(key, {N:16, r:1, p:1});

                    expect(function() {scrypt.verifyKdf(kdf, key);})
                        .to.throw(SyntaxError)
                        .to.match(/^SyntaxError: No callback function present, and Promises are not available$/);
                })

                it("Will throw a TypeError if the KDF is not a string or a Buffer object", function() {
                    expect(function(){scrypt.verifyKdf(1232,"key", function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: KDF type is incorrect: It can only be of type string or Buffer$/);
                });

                it("Will throw a TypeError if the key is not a string or a Buffer object", function() {
                    expect(function(){scrypt.verifyKdfSync("KDF", 1232, function(){})})
                        .to.throw(TypeError)
                        .to.match(/^TypeError: Key type is incorrect: It can only be of type string or Buffer$/);
                });
            });

            describe("Asynchronous functionality with correct arguments", function() {
                var key = "kdf"
                    , kdf = scrypt.kdfSync(key, {N:16, r:1, p:1});

                it("Will produce a boolean value", function(done){
                    scrypt.verifyKdf(kdf, key, function(err, result) {
                        expect(result)
                            .to.be.a('boolean')
                            .to.equal(true);
                        expect(err)
                            .to.not.exist;

                        scrypt.verifyKdf(kdf, "different key", function(err, result) {
                            expect(result)
                                .to.be.a('boolean')
                                .to.equal(false);
                            expect(err)
                                .to.not.exist;
                            done();
                        });
                    });
                });
            });

            describe("Promise asynchronous functionality with correct arguments", function() {
                var key = "kdf"
                    , kdf = scrypt.kdfSync(key, {N:16, r:1, p:1});

                if (typeof Promise !== "undefined") {
                    it("Will produce a boolean value", function(done){
                        scrypt.verifyKdf(kdf, key).then(function(result) {
                            expect(result)
                                .to.be.a('boolean')
                                .to.equal(true);

                            scrypt.verifyKdf(kdf, "different key").then(function(result) {
                                expect(result)
                                    .to.be.a('boolean')
                                    .to.equal(false);
                                done();
                            });
                        });
                    });
                }
            });
        });
    });

});