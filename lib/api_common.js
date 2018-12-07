'use strict';

// 本文件用于wechat API，基础文件，主要用于Token的处理和mixin机制
const httpx = require('httpx');
const liburl = require('url');


const UserAccessToken = function (data) {
  if (!(this instanceof UserAccessToken)) {
    return new UserAccessToken(data);
  }
  this.data = data;
};

/*!
 * 检查UserAccessToken是否有效，检查规则为当前时间和过期时间进行对比
 *
 * Examples:
 * ```
 * token.isValid();
 * ```
 */
UserAccessToken.prototype.isValid = function () {
  return !!this.data.access_token && (new Date().getTime()) < (this.data.create_at + (this.data.expires_in - 10) * 1000);
};


const AccessToken = function (accessToken, expireTime) {
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


const ComponentAccessToken = function (componentAccessToken, expireTime) {
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


const ComponentAPI = function({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken}) {
  if (!componentAppId || !componentAppSecret || !getComponentTicket || !getComponentToken || !saveComponentToken) {
    throw new Error('参数不完整');
  }
  this.component_appid = componentAppId;
  this.component_appsecret = componentAppSecret;
  this.getComponentTicket = getComponentTicket;
  this.getComponentToken = getComponentToken;
  this.saveComponentToken = saveComponentToken;
  this.prefix = 'https://api.weixin.qq.com/cgi-bin/';
  this.mpPrefix = 'https://mp.weixin.qq.com/cgi-bin/';
  this.defaults = {};
};

ComponentAPI.prototype.setOpts = function (opts) {
  this.defaults = opts;
};

/**
 * 设置urllib的hook
 */
ComponentAPI.prototype.request = function* (url, opts, retry) {
  if (typeof retry === 'undefined') {
    retry = 3;
  }

  let options = {};
  Object.assign(options, this.defaults);
  opts || (opts = {});
  let keys = Object.keys(opts);
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i];
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        Object.assign(options.headers, opts.headers);
      }
    }
  }

  let res = yield httpx.request(url, options);
  if (res.statusCode < 200 || res.statusCode > 204) {
    let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
    err.name = 'WeChatAPIError';
    throw err;
  }

  let buffer = yield httpx.read(res);
  let contentType = res.headers['content-type'] || '';
  if (contentType.indexOf('application/json') !== -1 || contentType.indexOf('text/plain') !== -1) {
    let data;
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

ComponentAPI.prototype.getComponentAccessToken = function* () {
  let url = `${this.prefix}component/api_component_token`;
  let ticket = yield  this.getComponentTicket();
  if (ticket) {
    this.component_verify_ticket = ticket;
  } else {
    ticket = this.component_verify_ticket;
  }
  let params = {
    'component_appid': this.component_appid,
    'component_appsecret': this.component_appsecret,
    'component_verify_ticket': ticket
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  let data = yield this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  let componentToken = new ComponentAccessToken(data.component_access_token, expireTime);
  yield  this.saveComponentToken(componentToken);
  return componentToken;
};


ComponentAPI.prototype.getComponentAccessToken = function* () {
  let url = `${this.prefix}component/api_component_token`;
  let ticket = yield  this.getComponentTicket();
  if (ticket) {
    this.component_verify_ticket = ticket;
  } else {
    ticket = this.component_verify_ticket;
  }
  let params = {
    'component_appid': this.component_appid,
    'component_appsecret': this.component_appsecret,
    'component_verify_ticket': ticket
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  let data = yield  this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  let componentToken = new ComponentAccessToken(data.component_access_token, expireTime);
  yield  this.saveComponentToken(componentToken);
  return componentToken;
}

/*!
 * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
 * 无需依赖 getComponentAccessToken 为前置调用。
 * 应用开发者无需直接调用此API。
 * Examples:
 * ```
 * yield  api.ensureComponentToken();
 * ```
 */
ComponentAPI.prototype.ensureComponentToken = function* () {
  let component_access_token = yield  this.getComponentToken();
  let accessToken;
  if (component_access_token && (accessToken = new ComponentAccessToken(component_access_token.componentAccessToken, component_access_token.expireTime)).isValid()) {
    return accessToken;
  }
  return yield  this.getComponentAccessToken();
}

/*!
 * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=8bf3492060bf2d58260b1c3e7878fc72867a891e& lang=zh_CN
 * ```
 * let preAuthCode = yield  api.getPreAuthCode();
 * ```
 * - `err`, 获取access token出现异常时的异常对象
 * - `result`, 成功时得到的响应结果 * Result:
 * ```
 * {"pre_auth_code":"Cx_Dk6qiBE0Dmx4EmlT3oRfArPvwSQ-oa3NL_fwHM7VI08r52wazoZX2Rhpz1dEw","expires_in":600}
 * ```
 */
ComponentAPI.prototype.getPreAuthCode = function* () {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_create_preauthcode?component_access_token=${componentAccessToken.componentAccessToken}`;
  let params = {
    component_appid: this.component_appid
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url,args);
}

/**
 * 获取授权地址
 * @param  redirect_url 
 */
ComponentAPI.prototype.getAppWebAuthorizeURL  = function*(redirect_url) {
  let {pre_auth_code} = yield  this.getPreAuthCode();
  if (!pre_auth_code) {
    throw new Error('获取授权码失败');
  }
  redirect_url = encodeURIComponent(redirect_url);
  return `${this.mpPrefix}componentloginpage?component_appid=${this.component_appid}&pre_auth_code=${pre_auth_code}&redirect_uri=${redirect_url}`;
}


/**
 * 获取授权地址
 * @param  redirect_url 
 */
ComponentAPI.prototype.getAppWechatAuthorizeURL = function* ({redirectUri, authType = 3, appId}) {
  let {pre_auth_code} = yield  this.getPreAuthCode();
  if (!pre_auth_code) {
    throw new Error('获取授权码失败');
  }
  redirectUri = encodeURIComponent(redirectUri);
  return `https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&no_scan=1&component_appid=${this.component_appid}&pre_auth_code=${pre_auth_code}&redirect_uri=${redirectUri}&auth_type=${authType}&biz_appid=${appId}#wechat_redirect`;
}

/**
 * 该API用于使用授权码换取授权公众号或小程序的授权信息，并换取authorizer_access_token和authorizer_refresh_token。 授权码的获取，需要在用户在第三方平台授权页中完成授权流程后，在回调URI中通* 过URL参数提供给第三方平台方。请注意，由于现在公众号或小程序可以自定义选择部分权限授权给第三方平台，因此第三方平台开发者需要通过该接口来获取公众号或小程序具体授权了哪些权限，而不是简单地认为自己* 声明的权限就是公众号或小程序授权的权限。
 * @param {*} authCode 预授权
 * 
 * @returns 
 * 
 * {
    "authorization_info": {
    "authorizer_appid": "wxf8b4f85f3a794e77",
    "authorizer_access_token": "QXjUqNqfYVH0yBE1iI_7vuN_9gQbpjfK7hYwJ3P7xOa88a89-Aga5x1NMYJyB8G2yKt1KCl0nPC3W9GJzw0Zzq_dBxc8pxIGUNi_bFes0qM",
    "expires_in": 7200,
    "authorizer_refresh_token": "dTo-YCXPL4llX-u1W1pPpnp8Hgm4wpJtlR6iV0doKdY",
    "func_info": [
    {
    "funcscope_category": {
    "id": 1
    }
    },
    {
    "funcscope_category": {
    "id": 2
    }
    },
    {
    "funcscope_category": {
    "id": 3
    }
    }
    ]
    }}
 */
ComponentAPI.prototype.getAuthorizationInfo = function* (authCode) {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_query_auth?component_access_token=${componentAccessToken.componentAccessToken}`;
  let params = {
    component_appid: this.component_appid,
    authorization_code: authCode
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url, args);
}

/**
 * 取授权方的帐号基本信息
 * 该API用于获取授权方的基本信息，包括头像、昵称、帐号类型、认证类型、微信号、原始ID和二维码图片URL。
 *
 * 需要特别记录授权方的帐号类型，在消息及事件推送时，对于不具备客服接口的公众号，需要在5秒内立即响应；而若有客服接口，则可以选择暂时不响应，而选择后续通过客服接口来发送消息触达粉丝。
 * 参见文档 https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=8bf3492060bf2d58260b1c3e7878fc72867a891e&lang=zh_CN
 */
ComponentAPI.prototype.getAuthorizerInfo = function* (appId) {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_get_authorizer_info?component_access_token=${componentAccessToken.componentAccessToken}`;
  let params = {
    component_appid: this.component_appid,
    authorizer_appid: appId
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url, args);
}


/*
 * 该API用于获取授权方的公众号或小程序的选项设置信息，如：地理位置上报，语音识别开关，多客服开关。注意，获取各项选项设置信息，需要有授权方的授权，详见权限集说明。
 * @param {*} optionName
 */
ComponentAPI.prototype.getAuthorizerOption = function* (optionName){
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_get_authorizer_option?component_access_token=${componentAccessToken.componentAccessToken}`;
  let params = {
    component_appid: this.component_appid,
    authorizer_appid: this.appId,
    option_name: optionName
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url, args);
}


/*
 * 该API用于获取授权方的公众号或小程序的选项设置信息，如：地理位置上报，语音识别开关，多客服开关。注意，获取各项选项设置信息，需要有授权方的授权，详见权限集说明。
 * @param {*} optionValue 
 * @returns
 * {
 *   "errcode":0,
 *   "errmsg":"ok"
 *  }
 */
ComponentAPI.prototype.setAuthorizerOption = function* (optionName, optionValue) {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_set_authorizer_option?component_access_token=${componentAccessToken.componentAccessToken}`;
  let params = {
    component_appid: this.component_appid,
    authorizer_appid: this.appId,
    option_name: optionName,
    option_value: optionValue
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url, args);
}

ComponentAPI.ComponentAccessToken = ComponentAccessToken;


const Oauth = function({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken, authorizerAppId, getUserToken, saveUserToken,  componentApi, isMiniProgram = false}) {
  if (componentApi && componentApi instanceof ComponentAPI) {
    this.componentApi = componentApi;
  } else if (componentAppId &&  componentAppSecret && getComponentTicket && getComponentToken && saveComponentToken) {
    componentApi = new ComponentAPI({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken});
    this.componentApi = componentApi;
  } else {
    throw new Error('参数不完整');
  }
  this.component_appid = componentApi.component_appid;
  this.component_appsecret = componentApi.component_appsecret;
  this.appid = authorizerAppId;
  this.isMiniProgram = isMiniProgram;
  this.ensureComponentToken =  function* () {
    return yield  componentApi.ensureComponentToken();
  };
  this.getUserToken = getUserToken || function* (openid) {
    return this.users[openid].data;
  };
  this.saveUserToken = saveUserToken || function*  (openid, token) {
    this.users[openid] = token;
    if (process.env.NODE_ENV === 'production') {
      console.warn('Don\'t save token in memory, when cluster or multi-computer!');
    }
  };
  this.users = {};
  this.prefix = 'https://api.weixin.qq.com/cgi-bin/';
  this.mpPrefix = 'https://mp.weixin.qq.com/cgi-bin/';
  this.defaults = {};
}


/**
 * 用于设置urllib的默认options * Examples:
 * ```
 * api.setOpts({timeout: 15000});
 * ```
 * @param {Object} opts 默认选项
 */
Oauth.prototype.setOpts = function (opts) {
  this.defaults = opts;
};

/**
 * 设置urllib的hook
 */
Oauth.prototype.request = function* (url, opts) {
  let options = {};
  Object.assign(options, this.defaults);
  opts || (opts = {});
  let keys = Object.keys(opts);
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i];
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        Object.assign(options.headers, opts.headers);
      }
    }
  }
  let res = yield  httpx.request(url, options);
  if (res.statusCode < 200 || res.statusCode > 204) {
    let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
    err.name = 'WeChatAPIError';
    throw err;
  }

  let buffer = yield  httpx.read(res);
  let contentType = res.headers['content-type'] || '';
  if (contentType.indexOf('application/json') !== -1 || contentType.indexOf('text/plain') !== -1) {
    let data;
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

      throw err;
    }

    return data;
  }

  return buffer;
}

Oauth.prototype.getUserAccessToken  = function* (code, codeType) {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `https://api.weixin.qq.com/sns/oauth2/component/access_token?appid=${this.appid}&code=${code}&grant_type=authorization_code&component_appid=${this.component_appid}&component_access_token=${componentAccessToken.componentAccessToken}`;
  let args = {
    method: 'post',
    data: JSON.stringify({}),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  let data = yield  this.request(url, args);
  data.create_at = new Date().getTime();
  let token = new UserAccessToken(data);
  yield  this.saveUserToken(data.openid, token, codeType);
  return token;
}


Oauth.prototype.refreshUserAccessToken   = function* (refreshToken){
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=${this.appid}&refresh_token=${refreshToken}&grant_type=refresh_token&component_appid=${this.component_appid}&component_access_token=${componentAccessToken.componentAccessToken}`;
  let args = {
    method: 'post',
    data: JSON.stringify({}),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  let data = yield  this.request(url, args);
  data.create_at = new Date().getTime();
  let token = new UserAccessToken(data);
  yield  this.saveUserToken(data.openid, token);
  return token;
}

Oauth.prototype._getUser= function* (options, accessToken)  {
  let url = `https://api.weixin.qq.com/sns/userinfo?access_token=${accessToken}&openid=${options && options.openid || options}&lang=${options && options.lang || 'zh_CN'}`;
  let args = {
    method: 'post',
    data: JSON.stringify({}),
    timeout: 10000,
    dataType: 'json',
    contentType: 'json'
  };
  return yield  this.request(url, args);
}

Oauth.prototype.getUserByCode = function* (options) {
  let lang, code;
  if (typeof options === 'string') {
    code = options;
  } else {
    lang = options.lang;
    code = options.code;
  }
  let token = yield  this.getUserAccessToken(code);
  return yield  this.getUser({openid: token.data.openid, lang: lang});
}

Oauth.prototype.getUser = function* (options) {
  if (typeof options !== 'object') {
    options = {
      openid: options
    };
  }
  let data = yield  this.getUserToken(options.openid);
  if (!data) {
    let error = new Error('No token for ' + options.openid + ', please authorize first.');
    error.name = 'NoOAuthTokenError';
    throw error;
  }
  let token = new UserAccessToken(data);
  let user;
  if (token.isValid()) {
    user = yield  this._getUser(options, token.data.access_token);
  } else {
    token = yield  this.refreshUserAccessToken(token.data.refresh_token);
    user = yield  this._getUser(options, token.data.access_token);
  }
  return user;
}


/**
 * 获取授权页面的URL地址
 * @param {String} redirect 授权后要跳转的地址
 * @param {String} state 开发者可提供的数据
 * @param {String} scope 作用范围，值为snsapi_userinfo和snsapi_base，前者用于弹出，后者用于跳转
 */

Oauth.prototype.getAuthorizeURL = function* (redirect, state, scope) {
  return `https://open.weixin.qq.com/connect/oauth2/authorize?appid=${this.appid}&component_appid=${this.component_appid}&response_type=code&scope=${scope || 'snsapi_base'}&state=${state}&redirect_uri=${redirect}#wechat_redirect`;
}

/**
 * 获取授权页面的URL地址
 * @param {String} redirect 授权后要跳转的地址
 * @param {String} state 开发者可提供的数据
 * @param {String} scope 作用范围，值为snsapi_login，前者用于弹出，后者用于跳转
 */
Oauth.prototype.getAuthorizeURLForWebsite = function* (redirect, state, scope) {
  return `https://open.weixin.qq.com/connect/qrconnect?appid=${this.appid}&component_appid=${this.component_appid}&response_type=code&scope=${scope || 'snsapi_login' }&state=${state}&redirect_uri=${redirect}#wechat_redirect`;
}

Oauth.UserAccessToken = UserAccessToken;





/**
 * 根据appid和appsecret创建API的构造函数
 * 如需跨进程跨机器进行操作Wechat API（依赖access token），access token需要进行全局维护
 * 使用策略如下： * 1. 调用用户传入的获取token的异步方法，获得token之后使用
 * 2. 使用appid/appsecret获取token。并调用用户传入的保存token方法保存 * Tips: * - 如果跨机器运行wechat模块，需要注意同步机器之间的系统时间。 * Examples:
 * ```
 * let API = require('wechat-api');
 * let api = new API('appid', 'secret');
 * ```
 * 以上即可满足单进程使用。
 * 当多进程时，token需要全局维护，以下为保存token的接口。
 * ```
 * let api = new API('appid', 'secret', function* () {
 *   // 传入一个获取全局token的方法
 *   let txt = yield fs.readFile('access_token.txt', 'utf8');
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
 * @param {Generator} getUserToken 可选的。获取全局用户token对象的方法，多进程模式部署时需在意
 * @param {Generator} saveUserToken 可选的。保存全局用户token对象的方法，多进程模式部署时需在意
 */
const API = function ({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken, authorizerAppId, getToken, saveToken, componentApi}) {
  if (componentApi && componentApi instanceof ComponentAPI) {
    this.componentApi = componentApi;
  } else if (componentAppId &&  componentAppSecret && getComponentTicket && getComponentToken && saveComponentToken) {
    this.componentApi = new ComponentAPI(componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken)
  } else {
    throw new Error('参数不完整');
  }
  this.component_appid = componentApi.component_appid;
  this.component_appsecret = componentApi.component_appsecret;
  this.appid = authorizerAppId;
  this.ensureComponentToken = function* () {
    return yield  componentApi.ensureComponentToken();
  };
  this.getToken = getToken || function*  () {
    return this.store;
  };
  this.saveToken = saveToken || function*  (accessToken, refreshToken) {
    this.store = {accessToken, refreshToken};
    if (process.env.NODE_ENV === 'production') {
      console.warn('Don\'t save token in memory, when cluster or multi-computer!');
    }
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

  let options = {};
  Object.assign(options, this.defaults);
  opts || (opts = {});
  let keys = Object.keys(opts);
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i];
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        Object.assign(options.headers, opts.headers);
      }
    }
  }

  let res = yield httpx.request(url, options);
  if (res.statusCode < 200 || res.statusCode > 204) {
    let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
    err.name = 'WeChatAPIError';
    throw err;
  }

  let buffer = yield httpx.read(res);
  let contentType = res.headers['content-type'] || '';
  if (contentType.indexOf('application/json') !== -1 || contentType.indexOf('text/plain') !== -1) {
    let data;
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
 * let token = yield api.getAccessToken();
 * ```
 * - `err`, 获取access token出现异常时的异常对象
 * - `result`, 成功时得到的响应结果 * Result:
 * ```
 * {"access_token": "ACCESS_TOKEN","expires_in": 7200}
 * ```
 */
API.prototype.getAccessToken = function* () {
  let componentAccessToken = yield this.ensureComponentToken();
  let url = `${this.prefix}component/api_authorizer_token?component_access_token=${componentAccessToken.componentAccessToken}`;
  let { accessToken, refreshToken } = (yield this.getToken()) || this.authorizer_refresh_token;
  let params = {
    'component_appid': this.component_appid,
    'authorizer_appid': this.appid,
    'authorizer_refresh_token': refreshToken
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    dataType: 'json',
    contentType: 'json'
  };
  if (accessToken) {
    accessToken = new AccessToken(accessToken.accessToken, accessToken.expireTime);
  }
  if (accessToken && accessToken.isValid()) {
    return accessToken;
  }
  let data = yield this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  accessToken = new AccessToken(data.authorizer_access_token, expireTime);
  refreshToken = data.authorizer_refresh_token;
  yield this.saveToken(accessToken, refreshToken);
  return accessToken;
};


/**
 * 用于设置urllib的默认options * Examples:
 * ```
 * api.setOpts({timeout: 15000});
 * ```
 * @param {Object} opts 默认选项
 */
API.prototype.setOpts = function(opts) {
  this.defaults = opts;
}

/**
 * 设置urllib的hook
 */
API.prototype.request = function* (url, opts, retry) {
  if (typeof retry === 'undefined') {
    retry = 3;
  }

  let options = {};
  Object.assign(options, this.defaults);
  opts || (opts = {});
  let keys = Object.keys(opts);
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i];
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        Object.assign(options.headers, opts.headers);
      }
    }
  }
  let res = yield  httpx.request(url, options);
  if (res.statusCode < 200 || res.statusCode > 204) {
    let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
    err.name = 'WeChatAPIError';
    throw err;
  }

  let buffer = yield  httpx.read(res);
  let contentType = res.headers['content-type'] || '';
  if (contentType.indexOf('application/json') !== -1) {
    let data;
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
        yield  this.saveToken(null);
        let token = yield  this.getAccessToken();
        let urlobj = liburl.parse(url, true);

        if (urlobj.query && urlobj.query.access_token) {
          urlobj.query.access_token = token.accessToken;
          delete urlobj.search;
        }

        return this.request(liburl.format(urlobj), opts, retry - 1);
      }

      throw err;
    }

    return data;
  }

  return buffer;
}

/*!
  * 该API用于在授权方令牌（authorizer_access_token）失效时，可用刷新令牌（authorizer_refresh_token）获取新的令牌。请注意，此处token是2小时刷新一次，开发者需要自行进行token的缓存，避免 * token的获取次数达到每日的限定额度。缓存方法可以参考：http://mp.weixin.qq.com/wiki/2/88b2bf1265a707c031e51f26ca5e6512.html
  * Examples:
  * ```
  * let token = yield  api.getAccessToken();
  * ```
  * - `err`, 获取access token出现异常时的异常对象
  * - `result`, 成功时得到的响应结果 * Result:
  * ```
  * {
  *   "authorizer_access_token": "aaUl5s6kAByLwgV0BhXNuIFFUqfrR8vTATsoSHukcIGqJgrc4KmMJ-JlKoC_-NKCLBvuU1cWPv4vDcLN8Z0pn5I45mpATruU0b51hzeT1f8", 
  *   "expires_in": 7200, 
  *   "authorizer_refresh_token": "BstnRqgTJBXb9N2aJq6L5hzfJwP406tpfahQeLNxX0w"
  * }
  * ```
  */
API.prototype.getAccessToken = function* () {
  let componentAccessToken = yield  this.ensureComponentToken();
  let url = `${this.prefix}component/api_authorizer_token?component_access_token=${componentAccessToken.componentAccessToken}`;
  let { refreshToken } = (yield  this.getToken());
  let params = {
    'component_appid': this.component_appid,
    'authorizer_appid': this.appid,
    'authorizer_refresh_token': refreshToken
  };
  let args = {
    method: 'post',
    data: JSON.stringify(params),
    dataType: 'json',
    contentType: 'json'
  };
  let data = yield  this.request(url, args);
  // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
  let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
  let token = new AccessToken(data.authorizer_access_token, expireTime);
  yield  this.saveToken(token, data.refreshToken);
  return token;
}

/*!
  * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
  * 无需依赖 getAccessToken 为前置调用。
  * 应用开发者无需直接调用此API。
  * Examples:
  * ```
  * yield  api.ensureAccessToken();
  * ```
  */
API.prototype.ensureAccessToken = function* () {
  // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
  let {accessToken} = yield  this.getToken();
  if (accessToken && (accessToken = new AccessToken(accessToken.accessToken, accessToken.expireTime)).isValid()) {
    return accessToken;
  }
  return yield  this.getAccessToken();
}
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
  Object.keys(obj).map(key=> {
    if (API.prototype.hasOwnProperty(key)) {
      throw new Error('Don\'t allow override existed prototype method. method: '+ key);
    }
    API.prototype[key] = obj[key];
  });
};


API.AccessToken = AccessToken;
module.exports = {API, Oauth, ComponentAPI};