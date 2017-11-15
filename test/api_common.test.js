'use strict';

const API = require('../');
const expect = require('expect.js');
const config = require('./config');

describe('api_common', function () {
  describe('isAccessTokenValid', function () {
    it('should invalid', function () {
      var token = new API.AccessToken('token', new Date().getTime() - 7200 * 1000);
      expect(token.isValid()).not.to.be.ok();
    });

    it('should valid', function () {
      var token = new API.AccessToken('token', new Date().getTime() + 7200 * 1000);
      expect(token.isValid()).to.be.ok();
    });
  });

  describe('isComponentAccessTokenValid', function () {
    it('should invalid', function () {
      var token = new API.ComponentAccessToken('componentAccessToken', new Date().getTime() - 7200 * 1000);
      expect(token.isValid()).not.to.be.ok();
    });

    it('should valid', function () {
      var token = new API.ComponentAccessToken('componentAccessToken', new Date().getTime() + 7200 * 1000);
      expect(token.isValid()).to.be.ok();
    });
  });

  describe('mixin', function () {
    it('should ok', function () {
      API.mixin({sayHi: function () {}});
      expect(API.prototype).to.have.property('sayHi');
    });

    it('should not ok when override method', function () {
      var obj = {sayHi: function () {}};
      expect(API.mixin).withArgs(obj).to.throwException(/Don't allow override existed prototype method\./);
    });
  });


  describe('getComponentAccessToken', function () {
    it('should ok', async function () {
      var api = new API(config.appid, config.appsecret);
      var token = await api.getComponentAccessToken();
      expect(token).to.only.have.keys('componentAccessToken', 'expireTime');
    });

    it('should not ok with invalid appid', async function () {
      var api = new API('appid', 'secret', 'error');
      try {
        await api.getComponentAccessToken();
      } catch (err) {
        expect(err).to.have.property('name', 'WeChatAPIError');
        expect(err).to.have.property('message');
        expect(err.message).to.match(/invalid appid/);
      }
    });

    it('should not ok with invalid appsecret', async function () {
      var api = new API(config.appid, 'appsecret');
      try {
        await api.getComponentAccessToken();
      } catch (err) {
        expect(err).to.have.property('name', 'WeChatAPIError');
        expect(err).to.have.property('message');
        expect(err.message).to.match(/invalid appsecret/);
      }
    });
  });

  describe('getAccessToken', function () {
    it('should ok', async function () {
      var api = new API(config.appid, config.appsecret,config.authorizerappid);
      var token = await api.getAccessToken();
      expect(token).to.only.have.keys('accessToken', 'expireTime');
    });

    it('should not ok with invalid appid', async function () {
      var api = new API('appid', 'secret');
      try {
        await api.getAccessToken();
      } catch (err) {
        expect(err).to.have.property('name', 'WeChatAPIError');
        expect(err).to.have.property('message');
        expect(err.message).to.match(/invalid appid/);
      }
    });

    it('should not ok with invalid appsecret', async function () {
      var api = new API(config.appid, config.appsecret);
      try {
        await api.getAccessToken();
      } catch (err) {
        expect(err).to.have.property('name', 'WeChatAPIError');
        expect(err).to.have.property('message');
        expect(err.message).to.match(/invalid appid/);
      }
    });
  });

});
