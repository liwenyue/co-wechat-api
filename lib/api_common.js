'use strict';

// 本文件用于wechat API，基础文件，主要用于Token的处理和mixin机制
const httpx = require('httpx');
const liburl = require('url');

var AccessToken = function (accessToken, expireTime) {
  if (!(this instanceof AccessToken)) {
    return new AccessToken(accessToken, expireTime);
  }
  this.accessToken = accessToken;
  this.expireTime = expireTime;
};

/*!
 * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
 * ```
 * token.isValid();
 * ```
 */
AccessToken.prototype.isValid = function () {
  return !!this.accessToken && (new Date().getTime()) < this.expireTime;
};


var ComponentAccessToken = function (componentAccessToken, expireTime) {
  if (!(this instanceof ComponentAccessToken)) {
    return new ComponentAccessToken(componentAccessToken, expireTime);
  }
  this.componentAccessToken = componentAccessToken;
  this.expireTime = expireTime;
};

/*!
 * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
 * ```
 * token.isValid();
 * ```
 */
ComponentAccessToken.prototype.isValid = function () {
  return !!this.componentAccessToken && (new Date().getTime()) < this.expireTime;
};

/**
 * 根据appid和appsecret创建API的构造函数
 * 如需跨进程跨机器进行操作Wechat API（依赖access token），access token需要进行全局维护
 * 使用策略如下： * 1. 调用用户传入的获取token的异步方法，获得token之后使用
 * 2. 使用appid/appsecret获取token。并调用用户传入的保存token方法保存 * Tips: * - 如果跨机器运行wechat模块，需要注意同步机器之间的系统时间。 * Examples:
 * ```
 * var API = require('wechat-api');
 * var api = new API('appid', 'secret');
 * ```
 * 以上即可满足单进程使用。
 * 当多进程时，token需要全局维护，以下为保存token的接口。
 * ```
 * var api = new API('appid', 'secret', function* () {
 *   // 传入一个获取全局token的方法
 *   var txt = yield fs.readFile('access_token.txt', 'utf8');
 *   return JSON.parse(txt);
 * }, function* (token) {
 *   // 请将token存储到全局，跨进程、跨机器级别的全局，比如写到数据库、redis等
 *   // 这样才能在cluster模式及多机情况下使用，以下为写入到文件的示例
 *   yield fs.writeFile('access_token.txt', JSON.stringify(token));
 * });
 * ```
 * @param {String} componentAppid 在开放平台上申请得到的appid
 * @param {String} componentAppSecret 在开放平台上申请得到的app secret
 *  * @param {String} authorizerAppid 在公众平台上申请得到的appid
 * @param {String} componentVerifyTicket 在开放平台推送的Ticket
 * @param {Generator} getComponentTicket 可选的。获取全局token对象的方法，多进程模式部署时需在意
 * @param {Generator} getComponentToken 可选的。获取全局token对象的方法，多进程模式部署时需在意
 * @param {Generator} saveComponentToken 可选的。保存全局token对象的方法，多进程模式部署时需在意
 * @param {Generator} getToken 可选的。获取全局token对象的方法，多进程模式部署时需在意
 * @param {Generator} saveToken 可选的。保存全局token对象的方法，多进程模式部署时需在意
 */
var API = function (componentAppid, componentAppSecret, authorizerAppid, componentVerifyTicket, getComponentTicket, getComponentToken, saveComponentToken, getToken, saveToken, authorizerRefreshToken) {
  this.component_appid = componentAppid;
  this.component_appsecret = componentAppSecret;
  this.appid = authorizerAppid;
  this.authorizer_refresh_token = authorizerRefreshToken;
  this.component_verify_ticket = componentVerifyTicket;
  this.getComponentToken = getComponentToken || function* () {
    return this.ComponentTokenStore;
  };
  this.saveComponentToken = saveComponentToken || function* (componentToken) {
    this.ComponentTokenStore = componentToken;
    if (process.env.NODE_ENV === 'production') {
      console.warn('Don\'t save component token in memory, when cluster or multi-computer!');
    }
  };
  this.getToken = getToken || function* () {
    return this.store;
  };
  this.saveToken = saveToken || function* (accessToken,refreshToken) {
    this.store = {accessToken, refreshToken};
    if (process.env.NODE_ENV === 'production') {
      console.warn('Don\'t save token in memory, when cluster or multi-computer!');
    }
  };
  this.getComponentTicket = getComponentTicket || function* () {
    return this.component_verify_ticket;
  };
  this.prefix = 'https://api.weixin.qq.com/cgi-bin/';
  this.mpPrefix = 'https://mp.weixin.qq.com/cgi-bin/';
  this.fileServerPrefix = 'http://file.api.weixin.qq.com/cgi-bin/';
  this.payPrefix = 'https://api.weixin.qq.com/pay/';
  this.merchantPrefix = 'https://api.weixin.qq.com/merchant/';
  this.customservicePrefix = 'https://api.weixin.qq.com/customservice/';
  this.defaults = {};
  // set default js ticket handle
  this.registerTicketHandle();
};

/**
 * 用于设置urllib的默认options * Examples:
 * ```
 * api.setOpts({timeout: 15000});
 * ```
 * @param {Object} opts 默认选项
 */
API.prototype.setOpts = function (opts) {
  this.defaults = opts;
};

/**
 * 设置urllib的hook
 */
API.prototype.request = function* (url, opts, retry) {
  if (typeof retry === 'undefined') {
    retry = 3;
  }

  var options = {};
  Object.assign(options, this.defaults);
  opts || (opts = {});
  var keys = Object.keys(opts);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        Object.assign(options.headers, opts.headers);
      }
    }
  }

  var res = yield httpx.request(url, options);
  if (res.statusCode < 200 || res.statusCode > 204) {
    var err = new Error(`url: ${url}, status code: ${res.statusCode}`);
    err.name = 'WeChatAPIError';
    throw err;
  }

  var buffer = yield httpx.read(res);
  var contentType = res.headers['content-type'] || '';
  if (contentType.indexOf('application/json') !== -1) {
    var data;
    try {
      data = JSON.parse(buffer);
    } catch (ex) {
      let err = new Error('JSON.parse error. buffer is ' + buffer.toString());
      err.name = 'WeChatAPIError';
      throw err;
    }

    if (data && data.errcode) {
      let err = new Error(data.errmsg);
      err.name = 'WeChatAPIError';
      err.code = data.errcode;

      if (err.code === 40001 && retry > 0) {
        // 销毁已过期的token
        yield this.saveToken(null);
        let token = yield this.getAccessToken();
        let urlobj = liburl.parse(url, true);

        if (urlobj.query && urlobj.query.access_token) {
          urlobj.query.access_token = token.accessToken;
          delete urlobj.search;
        }

        return yield this.request(liburl.format(urlobj), opts, retry - 1);
      }

      throw err;
    }

    return data;
  }

  return buffer;
};

/*!
 * 根据创建API时传入的appid和appsecret获取access token
 * 进行后续所有API调用时，需要先获取access token
 * 详细请看：<http://mp.weixin.qq.com/wiki/index.php?title=获取access_token> * 应用开发者无需直接调用本API。 * Examples:
 * ```
 * var token = yield api.getAccessToken();
 * ```
 * - `err`, 获取access token出现异常时的异常对象
 * - `result`, 成功时得到的响应结果 * Result:
 * ```
 * {"access_token": "ACCESS_TOKEN","expires_in": 7200}
 * ```
 */
API.prototype.getAccessToken = function* () {
  var componentAccessToken = yield this.ensureComponentToken();
  var url = `${this.prefix}component/api_authorizer_token?component_access_token=${componentAccessToken.componentAccessToken}`;
  let { refreshToken } = (yield this.getToken()) || this.authorizer_refresh_token;
  var params = {
    'component_appid': this.component_appid,
    'authorizer_appid': this.appid,
    'authorizer_refresh_token': refreshToken
  };
  var args = {
    method: 'post',
    data: JSON.stringify(params),
    dataType: 'json',
    contentType: 'json'
  };
  var data = yield this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  var expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  var accessToken = new AccessToken(data.authorizer_access_token, expireTime);
  refreshToken = data.authorizer_refresh_token;
  yield this.saveToken(accessToken, refreshToken);
  return accessToken;
};


API.prototype.getPerAuthCode = function *() {
  let componentAccessToken = yield this.ensureComponentToken();
  let url = `https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=${componentAccessToken.componentAccessToken}`;
  let args = {
    component_appid: this.appid
  };
  var data = yield this.request(url, args);
  if (data && data['pre_auth_code']) {
    return data['pre_auth_code'];
  } 
};


API.prototype.getAuthorizeURL = function* (redirect_url) {
  let preAuthCode = yield this.getPerAuthCode();
  if (!preAuthCode) {
    throw new Error('获取授权码失败');
  }
  redirect_url = encodeURIComponent(redirect_url);
  return `${this.prefix}componentloginpage?component_appid=${this.component_appid}&pre_auth_code=${preAuthCode}&redirect_uri=${redirect_url}`;
};


API.prototype.getAuthorizationInfo = function* (authCode) {
  var componentAccessToken = yield this.ensureComponentToken();
  let url = `${this.prefix}component/api_get_authorizer_info?component_access_token=${componentAccessToken.componentAccessToken}`;
  let args = {
    component_appid: this.component_appid,
    authorizer_appid: this.appid
  };
  var data = yield this.request(url, args);
  if (data && data['authorizer_info']) {
    var expireTime = (new Date().getTime()) + (data['authorizer_info'].expires_in - 10) * 1000;
    var accessToken = new AccessToken(data['authorizer_info'].authorizer_access_token, expireTime);
    let refreshToken = data.authorizer_refresh_token;
    yield this.saveToken(accessToken, refreshToken);
    return data['authorizer_info'];
  }
};


API.prototype.getComponentAccessToken = function* () {
  var url = this.prefix + 'component/api_component_token';
  let ticket = yield this.getComponentTicket();
  if (ticket) {
    this.component_verify_ticket = ticket;
  } else {
    ticket = this.component_verify_ticket;
  }
  var params = {
    'component_appid': this.component_appid,
    'component_appsecret': this.component_appsecret,
    'component_verify_ticket': ticket
  };
  var args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  var data = yield this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  var expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  var componentToken = new ComponentAccessToken(data.component_access_token, expireTime);
  yield this.saveComponentToken(componentToken);
  return componentToken;
};

/*!
 * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
 * 无需依赖getAccessToken为前置调用。
 * 应用开发者无需直接调用此API。
 * Examples:
 * ```
 * yield api.ensureAccessToken();
 * ```
 */
API.prototype.ensureAccessToken = function* () {
  // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
  var token = yield this.getToken();
  var accessToken;
  if (token && (accessToken = AccessToken(token.accessToken, token.expireTime)).isValid()) {
    return accessToken;
  }
  return yield this.getAccessToken();
};


/*!
 * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
 * 无需依赖getAccessToken为前置调用。
 * 应用开发者无需直接调用此API。
 * Examples:
 * ```
 * yield api.ensureAccessToken();
 * ```
 */
API.prototype.ensureComponentToken = function* () {
  // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
  var component_access_token = yield this.getComponentToken();
  var accessToken;
  if (component_access_token && (accessToken = new ComponentAccessToken(component_access_token.componentAccessToken, component_access_token.expireTime)).isValid()) {
    return accessToken;
  }
  return yield this.getComponentAccessToken();
};
/**
 * 用于支持对象合并。将对象合并到API.prototype上，使得能够支持扩展
 * Examples:
 * ```
 * // 媒体管理（上传、下载）
 * API.mixin(require('./lib/api_media'));
 * ```
 * @param {Object} obj 要合并的对象
 */
API.mixin = function (obj) {
  for (var key in obj) {
    if (API.prototype.hasOwnProperty(key)) {
      throw new Error('Don\'t allow override existed prototype method. method: '+ key);
    }
    API.prototype[key] = obj[key];
  }
};

API.AccessToken = AccessToken;
API.ComponentAccessToken = ComponentAccessToken;
module.exports = API;
