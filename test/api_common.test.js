'use strict';

const {API, ComponentAPI, Oauth} = require('../');
const expect = require('expect.js');
const config = require('./config');

describe('api_common', function () {
  describe('isAccessTokenValid', function () {
    it('should invalid', function () {
      let token = new API.AccessToken('token', new Date().getTime() - 7200 * 1000);
      expect(token.isValid()).not.to.be.ok();
    });

    it('should valid', function () {
      let token = new API.AccessToken('token', new Date().getTime() + 7200 * 1000);
      expect(token.isValid()).to.be.ok();
    });
  });

  describe('isComponentAccessTokenValid', function () {
    it('should invalid', function () {
      let token = new ComponentAPI.ComponentAccessToken('componentAccessToken', new Date().getTime() - 7200 * 1000);
      expect(token.isValid()).not.to.be.ok();
    });

    it('should valid', function () {
      let token = new ComponentAPI.ComponentAccessToken('componentAccessToken', new Date().getTime() + 7200 * 1000);
      expect(token.isValid()).to.be.ok();
    });
  });

  describe('isUserTokenValid', function () {
    it('should invalid', function () {
      let data = {
        create_at: new Date().getTime() - 7200 * 1000,
        expires_in: 7200,
        access_token: 'userAccessToken'
      };
      let token = new Oauth.UserAccessToken(data);
      expect(token.isValid()).not.to.be.ok();
    });

    it('should valid', function () {
      let data = {
        create_at: new Date().getTime() + 7200 * 1000,
        expires_in: 7200,
        access_token: 'userAccessToken'
      };
      let token = new Oauth.UserAccessToken(data);
      expect(token.isValid()).to.be.ok();
    });
  });

  describe('mixin', function () {
    it('should ok', function () {
      API.mixin({sayHi: function () {}});
      expect(API.prototype).to.have.property('sayHi');
    });

    it('should not ok when override method', function () {
      let obj = {sayHi: function () {}};
      expect(API.mixin).withArgs(obj).to.throwException(/Don't allow override existed prototype method\./);
    });
  });

  
  describe('createComponentApi', function () {
    it('should not ok create with not any props', async function () {
      try {
        let oauth = new Oauth({
          authorizerAppId: config.authorizerAppId,
          getUserToken: async function() {
            return {};
          },
          saveUserToken: async function(token) {
  
          }
        });
      } catch (err) {
        expect(err.message).to.equal('参数不完整');
      }
    });
    it('should have ensureComponentToken', async function () {
      let api = new ComponentAPI({
        componentAppId: config.componentAppId,
        componentAppSecret: config.componentAppSecret,
        getComponentTicket: async function() {
          return config.componentTicket;
        },
        getComponentToken: async function() {
          return {accessToken: '', expireTime: ''};
        },
        saveComponentToken: async function(token) {
          
        }
      });
      expect(api).to.have.property('ensureComponentToken');
    });

    it('should not ok create with not componentAPI', async function () {
      try {
        let oauth = new Oauth({
          authorizerAppId: config.authorizerAppId,
          getUserToken: async function() {
            return {};
          },
          saveUserToken: async function(token) {
  
          }
        });
      } catch (err) {
        expect(err.message).to.equal('参数不完整');
      }
    });

    it('should ok create with componentAPI', async function () {
      let componentApi = new ComponentAPI({
        componentAppId: config.componentAppId,
        componentAppSecret: config.componentAppSecret,
        getComponentTicket: async function() {
          return 'getComponentTicket';
        },
        getComponentToken: async function() {
          return {accessToken: '', expireTime: ''};
        },
        saveComponentToken: async function(token) {
          
        }
      });
      expect(componentApi).to.have.property('component_appid', config.componentAppId);
      expect(componentApi).to.have.property('component_appsecret', config.componentAppSecret);
      expect(componentApi).to.have.keys('ensureComponentToken','getComponentTicket', 'getComponentToken', 'saveComponentToken');
    });

  });

  describe('createOauth', function () {
    it('should not ok create with not componentAPI', async function () {
      try {
        let oauth = new Oauth({
          authorizerAppId: config.authorizerAppId,
          getUserToken: async function() {
            return {};
          },
          saveUserToken: async function(token) {
  
          }
        });
      } catch (err) {
        expect(err.message).to.equal('参数不完整');
      }
    });

    it('should ok create with componentAPI', async function () {
      let componentApi = new ComponentAPI({
        componentAppId: config.componentAppId,
        componentAppSecret: config.componentAppSecret,
        getComponentTicket: async function() {
          return 'getComponentTicket';
        },
        getComponentToken: async function() {
          return {accessToken: '', expireTime: ''};
        },
        saveComponentToken: async function(token) {
          
        }
      });
      let oauth = new Oauth({
        authorizerAppid: config.authorizerAppid,
        getUserToken: async function() {
          return {};
        },
        saveUserToken: async function(token) {

        },
        componentApi
      });
      expect(oauth).to.have.property('component_appid', config.componentAppId);
      expect(oauth).to.have.property('component_appsecret', config.componentAppSecret);
      expect(oauth).to.have.keys('ensureComponentToken','getUserToken', 'saveUserToken', 'componentApi');
      expect(oauth).to.have.property('componentApi',componentApi);
    });
  });


  describe('createAPI', function () {
    it('should not ok create with not componentAPI', async function () {
      try {
        let api = new API({
          authorizerAppId: config.authorizerAppId,
          getToken: async function() {
            return {};
          },
          saveToken: async function(token) {
  
          }
        });
      } catch (err) {
        expect(err.message).to.equal('参数不完整');
      }
    });

    it('should ok create with componentAPI', async function () {
      let componentApi = new ComponentAPI({
        componentAppId: config.componentAppId,
        componentAppSecret: config.componentAppSecret,
        getComponentTicket: async function() {
          return 'getComponentTicket';
        },
        getComponentToken: async function() {
          return {accessToken: '', expireTime: ''};
        },
        saveComponentToken: async function(token) {
          
        }
      });
      let api = new API({
        authorizerAppid: config.authorizerAppid,
        getUserToken: async function() {
          return {};
        },
        saveUserToken: async function(token) {

        },
        componentApi
      });
      expect(api).to.have.property('component_appid', config.componentAppId);
      expect(api).to.have.property('component_appsecret', config.componentAppSecret);
      expect(api).to.have.keys('ensureComponentToken','getToken', 'saveToken', 'componentApi');
      expect(api).to.have.property('componentApi',componentApi);
    });
  });

  describe('getAccessToken', function () {
    it('should ok', async function () {
      let api = new API(config.appid, config.appsecret,config.authorizerappid);
      let token = await api.getAccessToken();
      expect(token).to.only.have.keys('accessToken', 'expireTime');
    });

    it('should not ok with invalid appid', async function () {
      let api = new API('appid', 'secret');
      try {
        await api.getAccessToken();
      } catch (err) {
        expect(err).to.have.property('name', 'WeChatAPIError');
        expect(err).to.have.property('message');
        expect(err.message).to.match(/invalid appid/);
      }
    });

    it('should not ok with invalid appsecret', async function () {
      let api = new API(config.appid, config.appsecret);
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
