'use strict';

// 本文件用于wechat API，基础文件，主要用于Token的处理和mixin机制
const httpx = require('httpx');
const liburl = require('url');
const WxBizDataCrypt = require('./wx_biz_data_crypt');
class AccessToken {
  constructor(accessToken, expireTime) {
    this.accessToken = accessToken;
    this.expireTime = expireTime;
  }

  /*!
   * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
   * ```
   * token.isValid();
   * ```
   */
  isValid() {
    return !!this.accessToken && (new Date().getTime()) < this.expireTime;
  }
}
/*!
   * 检查ComponentAccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
   * ```
   * componentAccessToken.isValid();
   * ```
   */
class ComponentAccessToken {
  constructor(componentAccessToken, expireTime) {
    this.componentAccessToken = componentAccessToken;
    this.expireTime = expireTime;
  }

  /*!
   * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
   * ```
   * token.isValid();
   * ```
   */
  isValid() {
    return !!this.componentAccessToken && (new Date().getTime()) < this.expireTime;
  }
}



class UserAccessToken {
  constructor(data) {
    this.data = data;
  }

  /*!
   * 检查AccessToken是否有效，检查规则为当前时间和过期时间进行对比 * Examples:
   * ```
   * token.isValid();
   * ```
   */
  isValid() {
    return !!this.data.access_token && (new Date().getTime()) < (this.data.create_at + (this.data.expires_in - 10) * 1000);
  }
}

class ComponentAPI {
/**
   * 使用方式如下
   * const api = new WeChatOpenApi(config.open.appId, config.open.appSecret, appId,
   * async () {
   *   let ticket = await redis.get(`${config.open.appId}:ComponentVerifyTicket`,config.wxCacheDb);
   *   //console.log(`get ${config.open.appId}:ComponentVerifyTicket`,  ticket );
   *   return ticket;
   * },
   * async (){
   *   let result = await redis.get(`${config.open.appId}:componentAccessToken`,config.wxCacheDb);
   *   //console.log(`get componentAccessToken`,  result);
   *   return JSON.parse(result);
   * },
   * async (token) {
   *   //console.log(`save componentAccessToken`,  token);
   *   await redis.set(`${config.open.appId}:componentAccessToken`,JSON.stringify(token),config.wxCacheDb);
   * },
   * //this.openApis[appId] = api;
   * return api;
   * ```
   * @param {String} componentAppId 第三方平台appid
   * @param {String} componentAppSecret 第三方平台appSecret
   * @param {String} 
   * @param {Function} getComponentTicket componentVerifyTicket 微信后台推送的ticket，
   * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&lang=zh_CN
   * @param {Function} getComponentToken 必选。获取全局token对象的方法，多进程模式部署时需在意
   * @param {Function} saveComponentToken 必选的。保存全局token对象的方法，多进程模式部署时需在意
   */
  constructor({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken}) {
    if (!componentAppId || !componentAppSecret || !getComponentTicket || !getComponentToken || !saveComponentToken) {
      throw new Error('参数不完整');
    }
    this.componentAppId = componentAppId;
    this.componentAppSecret = componentAppSecret;
    this.getComponentTicket = getComponentTicket;
    this.getComponentToken = getComponentToken;
    this.saveComponentToken = saveComponentToken;
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
  setOpts(opts) {
    this.defaults = opts;
  }

  /**
   * 设置urllib的hook
   */
  async request(url, opts) {
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
    let res = await httpx.request(url, options);
    if (res.statusCode < 200 || res.statusCode > 204) {
      let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
      err.name = 'WeChatAPIError';
      throw err;
    }

    let buffer = await httpx.read(res);
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

        throw err;
      }

      return data;
    }

    return buffer;
  }


  async getComponentAccessToken () {
    let url = `${this.prefix}component/api_component_token`;
    let ticket = await this.getComponentTicket();
    if (ticket) {
      this.component_verify_ticket = ticket;
    } else {
      ticket = this.component_verify_ticket;
    }
    let params = {
      'component_appid': this.componentAppId,
      'component_appsecret': this.componentAppSecret,
      'component_verify_ticket': ticket
    };
    let args = {
      method: 'post',
      data: JSON.stringify(params),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    let data = await this.request(url, args);
    // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
    let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
    let componentToken = new ComponentAccessToken(data.component_access_token, expireTime);
    await this.saveComponentToken(componentToken);
    return componentToken;
  }

  /*!
   * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
   * 无需依赖 getComponentAccessToken 为前置调用。
   * 应用开发者无需直接调用此API。
   * Examples:
   * ```
   * await api.ensureComponentToken();
   * ```
   */
  async ensureComponentToken() {
    let component_access_token = await this.getComponentToken();
    let accessToken;
    if (component_access_token && (accessToken = new ComponentAccessToken(component_access_token.componentAccessToken, component_access_token.expireTime)).isValid()) {
      return accessToken;
    }
    return await this.getComponentAccessToken();
  }

  /*!
   * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=8bf3492060bf2d58260b1c3e7878fc72867a891e& lang=zh_CN
   * ```
   * let preAuthCode = await api.getPreAuthCode();
   * ```
   * - `err`, 获取access token出现异常时的异常对象
   * - `result`, 成功时得到的响应结果 * Result:
   * ```
   * {"pre_auth_code":"Cx_Dk6qiBE0Dmx4EmlT3oRfArPvwSQ-oa3NL_fwHM7VI08r52wazoZX2Rhpz1dEw","expires_in":600}
   * ```
   */
  async getPreAuthCode () {
    let componentAccessToken = await this.ensureComponentToken();
    let url = `${this.prefix}component/api_create_preauthcode?component_access_token=${componentAccessToken.componentAccessToken}`;
    let params = {
      component_appid: this.componentAppId
    };
    let args = {
      method: 'post',
      data: JSON.stringify(params),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    return await this.request(url,args);
  }

  /**
   * 获取授权地址
   * @param  redirect_url 
   */
  async getAppWebAuthorizeURL (redirect_url) {
    let {pre_auth_code} = await this.getPreAuthCode();
    if (!pre_auth_code) {
      throw new Error('获取授权码失败');
    }
    redirect_url = encodeURIComponent(redirect_url);
    return `${this.mpPrefix}componentloginpage?component_appid=${this.componentAppId}&pre_auth_code=${pre_auth_code}&redirect_uri=${redirect_url}`;
  }


  /**
   * 获取授权地址
   * @param  redirect_url 
   */
  async getAppWechatAuthorizeURL ({redirectUri, authType = 3, appId}) {
    let {pre_auth_code} = await this.getPreAuthCode();
    if (!pre_auth_code) {
      throw new Error('获取授权码失败');
    }
    redirectUri = encodeURIComponent(redirectUri);
    return `https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&no_scan=1&component_appid=${this.componentAppId}&pre_auth_code=${pre_auth_code}&redirect_uri=${redirectUri}&auth_type=${authType}&biz_appid=${appId}#wechat_redirect`;
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
  async getAuthorizationInfo (authCode) {
    let componentAccessToken = await this.ensureComponentToken();
    let url = `${this.prefix}component/api_query_auth?component_access_token=${componentAccessToken.componentAccessToken}`;
    let params = {
      component_appid: this.componentAppId,
      authorization_code: authCode
    };
    let args = {
      method: 'post',
      data: JSON.stringify(params),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    return await this.request(url, args);
  }

  /**
   * 取授权方的帐号基本信息
   * 该API用于获取授权方的基本信息，包括头像、昵称、帐号类型、认证类型、微信号、原始ID和二维码图片URL。
   *
   * 需要特别记录授权方的帐号类型，在消息及事件推送时，对于不具备客服接口的公众号，需要在5秒内立即响应；而若有客服接口，则可以选择暂时不响应，而选择后续通过客服接口来发送消息触达粉丝。
   * 参见文档 https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=8bf3492060bf2d58260b1c3e7878fc72867a891e&lang=zh_CN
   */
  async getAuthorizerInfo (appId) {
    let componentAccessToken = await this.ensureComponentToken();
    let url = `${this.prefix}component/api_get_authorizer_info?component_access_token=${componentAccessToken.componentAccessToken}`;
    let params = {
      component_appid: this.componentAppId,
      authorizer_appid: appId
    };
    let args = {
      method: 'post',
      data: JSON.stringify(params),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    return await this.request(url, args);
  }


  /*
   * 该API用于获取授权方的公众号或小程序的选项设置信息，如：地理位置上报，语音识别开关，多客服开关。注意，获取各项选项设置信息，需要有授权方的授权，详见权限集说明。
   * @param {*} optionName
   */
  async getAuthorizerOption(optionName) {
    let componentAccessToken = await this.ensureComponentToken();
    let url = `${this.prefix}component/api_get_authorizer_option?component_access_token=${componentAccessToken.componentAccessToken}`;
    let params = {
      component_appid: this.componentAppId,
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
    return await this.request(url, args);
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
  async setAuthorizerOption(optionName, optionValue) {
    let componentAccessToken = await this.ensureComponentToken();
    let url = `${this.prefix}component/api_set_authorizer_option?component_access_token=${componentAccessToken.componentAccessToken}`;
    let params = {
      component_appid: this.componentAppId,
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
    return await this.request(url, args);
  }
}

ComponentAPI.ComponentAccessToken = ComponentAccessToken;

class Oauth {
  /**
   * 
   * 使用方式如下
   * const api = new WeChatOpenApi(config.open.appId, config.open.appSecret, appId,
   * async () {
   *   let ticket = await redis.get(`${config.open.appId}:ComponentVerifyTicket`,config.wxCacheDb);
   *   //console.log(`get ${config.open.appId}:ComponentVerifyTicket`,  ticket );
   *   return ticket;
   * },
   * async (){
   *   let result = await redis.get(`${config.open.appId}:componentAccessToken`,config.wxCacheDb);
   *   //console.log(`get componentAccessToken`,  result);
   *   return JSON.parse(result);
   * },
   * async (token) {
   *   //console.log(`save componentAccessToken`,  token);
   *   await redis.set(`${config.open.appId}:componentAccessToken`,JSON.stringify(token),config.wxCacheDb);
   * },
   * //this.openApis[appId] = api;
   * return api;
   * ```
   * @param {String} componentAppId 第三方平台appid
   * @param {String} componentAppSecret 第三方平台appSecret
   * @param {String} 
   * @param {Function} getComponentTicket componentVerifyTicket 微信后台推送的ticket，
   * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&lang=zh_CN
   * @param {Function} getComponentToken 必选。获取全局token对象的方法，多进程模式部署时需在意
   * @param {Function} saveComponentToken 必选的。保存全局token对象的方法，多进程模式部署时需在意
   * 文档地址 https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318590&token=8bf3492060bf2d58260b1c3e7878fc72867a891e&*lang=zh_CN
   */
  constructor({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken, authorizerAppId, getUserToken, saveUserToken, componentApi, appId, appSecret, isMiniProgram = false }) {
    if (componentApi && componentApi instanceof ComponentAPI) {
      this.componentApi = componentApi;
      this.componentAppId = componentApi.componentAppId;
      this.componentAppSecret = componentApi.componentAppSecret;
    } else if (componentAppId &&  componentAppSecret && getComponentTicket && getComponentToken && saveComponentToken) {
      componentApi = new ComponentAPI({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken});
      this.componentApi = componentApi;
      this.componentAppId = componentApi.componentAppId;
      this.componentAppSecret = componentApi.componentAppSecret;
    } else if (appSecret) {
      this.appSecret = appSecret;
    } else {
      throw new Error('参数不完整');
    }
    this.appId = authorizerAppId || appId;
    this.isMiniProgram = isMiniProgram;
    this.ensureComponentToken = async function() {
      if (this.appSecret) {
        return {};
      }
      return await componentApi.ensureComponentToken();
    };
    this.getUserToken = getUserToken || async function(openid) {
      return this.users[openid].data;
    };
    this.saveUserToken = saveUserToken || async function (openid, token) {
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
  setOpts(opts) {
    this.defaults = opts;
  }

  /**
   * 设置urllib的hook
   */
  async request(url, opts) {
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
    let res = await httpx.request(url, options);
    if (res.statusCode < 200 || res.statusCode > 204) {
      let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
      err.name = 'WeChatAPIError';
      throw err;
    }

    let buffer = await httpx.read(res);
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

  async getUserAccessToken (code) {
    let baseUrl;
    let params;
    if (this.componentApi) {
      let componentAccessToken = await this.ensureComponentToken();
      params = {
        appid: this.appId,
        code: code,
        grant_type: 'authorization_code',
        component_appid: this.componentAppId,
        component_access_token: componentAccessToken.componentAccessToken
      };
      baseUrl = 'https://api.weixin.qq.com/sns/oauth2/component';
    } else {
      params = {
        appid: this.appId,
        secret: this.appSecret,
        code: code,
        grant_type: 'authorization_code'
      };
      baseUrl = 'https://api.weixin.qq.com/sns/oauth2';
    }
    let url = this.getRequestUrl(`${baseUrl}/access_token`, params);
    let args = {
      method: 'post',
      data: JSON.stringify({}),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    let data = await this.request(url, args);
    data.create_at = new Date().getTime();
    let token = new UserAccessToken(data);
    await this.saveUserToken(data.openid, token);
    return token;
  }
  

  toUrl (url, query, excepts) {
    return `${url}?${Object.keys(query).filter(key => !~excepts.indexOf(key)).map(key => `${key}=${query[key]}`).join('&')}`;
  }

  getRequestUrl (url, query) {
    if (this.appSecret) {
      return this.toUrl(url, query, ['component_appid', 'component_access_token']);
    } 
    return this.toUrl(url, query, ['secret']);
  }
  
  async refreshUserAccessToken (refreshToken) {
    let params;
    let baseUrl;
    if (this.componentApi) {
      let componentAccessToken = await this.ensureComponentToken();
      // let url = `https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=${this.appId}&refresh_token=${refreshToken}&grant_type=refresh_token&component_appid=${this.componentAppId}&component_access_token=${componentAccessToken.componentAccessToken}`;
      params =  {
        appid: this.appId,
        secret: this.appSecret,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        component_appid: this.componentAppId,
        component_access_token: componentAccessToken.componentAccessToken
      };
      baseUrl = 'https://api.weixin.qq.com/sns/oauth2/component';
    } else {
      params = {
        appid: this.appId,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }
      baseUrl = 'https://api.weixin.qq.com/sns/oauth2';
    }
    let url = this.getRequestUrl(`${baseUrl}/refresh_token`, params)
    
    let args = {
      method: 'post',
      data: JSON.stringify({}),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    let data = await this.request(url, args);
    data.create_at = new Date().getTime();
    let token = new UserAccessToken(data);
    await this.saveUserToken(data.openid, token);
    return token;
  }
  
  async _getUser (options, accessToken) {
    let url = `https://api.weixin.qq.com/sns/userinfo?access_token=${accessToken}&openid=${options && options.openid || options}&lang=${options && options.lang || 'zh_CN'}`;
    let args = {
      method: 'post',
      data: JSON.stringify({}),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    return await this.request(url, args);
  }

  /**
   * 根据授权获取到的code，换取小程序的session key和openid（以及有条件下的unionid）
   * 获取openid之后，可以调用`wechat.API`来获取更多信息
   * Examples:
   * ```
   * api.getSessionKey(code, callback);
   * ```
   * Callback:
   *
   * - `err`, 获取session key出现异常时的异常对象
   * - `result`, 成功时得到的响应结果
   *
   * Result:
   * ```
   * {
   *  data: {
   *    "session_key": "SESSION_KEY",
   *    "openid": "OPENID",
   *    "unionid": "UNIONID"
   *  }
   * }
   * ```
   * @param {String} code 授权获取到的code
   */
  async getSessionKey (code) {
    let params;
    let baseUrl;
    if (this.componentApi) {
      let componentAccessToken = await this.ensureComponentToken();
      params = {
        appid: this.appId,
        secret: this.appSecret,
        js_code: code,
        grant_type: 'authorization_code',
        component_appid: this.componentAppId,
        component_access_token: componentAccessToken.componentAccessToken
      };
      baseUrl = 'https://api.weixin.qq.com/sns/component';
    } else {
      params = {
        appid: this.appId,
        secret: this.appSecret,
        js_code: code,
        grant_type: 'authorization_code',
      };

      baseUrl = 'https://api.weixin.qq.com/sns';
    }
    let url = this.getRequestUrl(`${baseUrl}/jscode2session`, params)
    
    let args = {
      method: 'post',
      data: JSON.stringify({}),
      timeout: 10000,
      dataType: 'json',
      contentType: 'json'
    };
    return await this.request(url, args);
  }

  /**
   * 根据服务器保存的sessionKey对从小程序客户端获取的加密用户数据进行解密
   * Examples:
   * ```
   * api.decryptMiniProgramUser({encryptedData, iv}, callback);
   * ```
   * Callback:
   *
   * - `err`, 解密用户信息出现异常时的异常对象
   * - `result`, 成功时得到的响应结果
   *
   * Result:
   * ```
   *{
   *    "openId": "OPENID",
   *    "nickName": "NICKNAME",
   *    "gender": "GENDER",
   *    "city": "CITY",
   *    "province": "PROVINCE",
   *    "country": "COUNTRY",
   *    "avatarUrl": "AVATARURL",
   *    "unionId": "UNIONID",
   *    "watermark":
   *    {
   *        "appid":"APPID",
   *        "timestamp":TIMESTAMP
   *    }
   *}
  * ```
  * @param {Object} options 需要解密的对象
  * @param {String} options.encryptedData 从小程序中获得的加密过的字符串
  * @param {String} options.iv 从小程序中获得的加密算法初始向量
  */
  decryptMiniProgramUser  (options) {
    var decrypter = new WxBizDataCrypt(this.appId, options.sessionKey);
    return decrypter.decryptData(options.encryptedData, options.iv);
  }

  async getUserByCode (options) {
    let lang, code;
    if (typeof options === 'string') {
      code = options;
    } else {
      lang = options.lang;
      code = options.code;
    }
    let user;
    let data;
    if (this.isMiniProgram) {
      data = await this.getSessionKey(code);
      try {
        user = this.decryptMiniProgramUser({
          sessionKey: data.session_key,
          encryptedData: options.encryptedData,
          iv: options.iv,
        });
      } catch (e) {
        console.error(e)
        return data;
      }
      return {...data, ...user};
    }
    let token = await this.getUserAccessToken(code);
    return await this.getUser({openid: token.data.openid, lang: lang});
  }

  async getUser (options) {
    if (typeof options !== 'object') {
      options = {
        openid: options
      };
    }
    let data = await this.getUserToken(options.openid);
    if (!data) {
      let error = new Error('No token for ' + options.openid + ', please authorize first.');
      error.name = 'NoOAuthTokenError';
      throw error;
    }
    let token = new UserAccessToken(data);
    let user;
    if (token.isValid()) {
      user = await this._getUser(options, token.data.access_token);
    } else {
      token = await this.refreshUserAccessToken(token.data.refresh_token);
      user = await this._getUser(options, token.data.access_token);
    }
    return user;
  }


  /**
   * 获取授权页面的URL地址
   * @param {String} redirect 授权后要跳转的地址
   * @param {String} state 开发者可提供的数据
   * @param {String} scope 作用范围，值为snsapi_userinfo和snsapi_base，前者用于弹出，后者用于跳转
   */

  getAuthorizeURL (redirect, state, scope) {
    if (this.componentAppId) {
      return `https://open.weixin.qq.com/connect/oauth2/authorize?appid=${this.appId}&component_appid=${this.componentAppId}&redirect_uri=${redirect}&response_type=code&scope=${scope || 'snsapi_base'}&state=${state}#wechat_redirect`;
    }
    return `https://open.weixin.qq.com/connect/oauth2/authorize?appid=${this.appId}&redirect_uri=${redirect}&response_type=code&scope=${scope || 'snsapi_base'}&state=${state}#wechat_redirect`;
    
  }

  /**
   * 获取授权页面的URL地址
   * @param {String} redirect 授权后要跳转的地址
   * @param {String} state 开发者可提供的数据
   * @param {String} scope 作用范围，值为snsapi_login，前者用于弹出，后者用于跳转
   */
  getAuthorizeURLForWebsite (redirect, state, scope) {
    if (this.componentAppId) {
      return `https://open.weixin.qq.com/connect/qrconnect?appid=${this.appId}&component_appid=${this.componentAppId}&response_type=code&scope=${scope || 'snsapi_login' }&state=${state}&redirect_uri=${redirect}#wechat_redirect`;
    }
    return `https://open.weixin.qq.com/connect/qrconnect?appid=${this.appId}&response_type=code&scope=${scope || 'snsapi_login' }&state=${state}&redirect_uri=${redirect}#wechat_redirect`;
  }
}

Oauth.UserAccessToken = UserAccessToken;

class API {
  /**
   * 使用方式如下
   * const api = new WeChatOpenApi(config.open.appId, config.open.appSecret, appId,
   * async () {
   *   let ticket = await redis.get(`${config.open.appId}:ComponentVerifyTicket`,config.wxCacheDb);
   *   //console.log(`get ${config.open.appId}:ComponentVerifyTicket`,  ticket );
   *   return ticket;
   * },
   * async (){
   *   let result = await redis.get(`${config.open.appId}:componentAccessToken`,config.wxCacheDb);
   *   //console.log(`get componentAccessToken`,  result);
   *   return JSON.parse(result);
   * },
   * async (token) {
   *   //console.log(`save componentAccessToken`,  token);
   *   await redis.set(`${config.open.appId}:componentAccessToken`,JSON.stringify(token),config.wxCacheDb);
   * },
   * async (){
   *   let accessToken = await redis.get(`${appId}:accessToken`);
   *   let refreshToken = await redis.get(`${appId}:refreshToken`);
   *   return {accessToken: JSON.parse(accessToken),refreshToken};
   * },
   * async (accessToken, refreshToken) {
   *   //console.log(`save accessToken, refreshToken`,  accessToken, refreshToken);
   *   await redis.set(`${appId}:accessToken`,JSON.stringify(accessToken));
   *   await redis.set(`${appId}:refreshToken`,refreshToken);
   * });
   * 
   * async getTicketToken() {
   *   // 传入一个获取全局token的方法
   *   let result = await redis.get(`${appId}:ticket`,config.wxCacheDb);
   *   return JSON.parse(result);
   * }
   *
   * async saveTicketToken(token) {
   *   await redis.set(`${appId}:ticket`,JSON.stringify(token),config.wxCacheDb);
   * }
   * api.registerTicketHandle(getTicketToken, saveTicketToken);
   * //this.openApis[appId] = api;
   * return api;
   * ```
   * @param {String} componentAppId 第三方平台appid
   * @param {String} componentAppSecret 第三方平台appSecret
   * @param {String} authorizerAppId 在公众平台上申请得到的appid
   * @param {String} componentVerifyTicket 微信后台推送的ticket，此ticket会定时推送，具体参考文档：推送component_verify_ticket协议
   * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&lang=zh_CN
   * @param {Function} getComponentTicket 可选的。获取全局token对象的方法，多进程模式部署时需在意
   * @param {Function} getComponentToken 可选的。获取全局token对象的方法，多进程模式部署时需在意
   * @param {Function} saveComponentToken 可选的。保存全局token对象的方法，多进程模式部署时需在意
   * @param {Function} getToken 可选的。获取全局token对象的方法，多进程模式部署时需在意
   * @param {Function} saveToken 可选的。保存全局token对象的方法，多进程模式部署时需在意
   */
  constructor({componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken, authorizerAppId, getToken, saveToken, componentApi, appId, appSecret, tokenFromCustom}) {
    if (componentApi && componentApi instanceof ComponentAPI) {
      this.componentApi = componentApi;
      this.componentAppId = componentApi.componentAppId;
      this.componentAppSecret = componentApi.componentAppSecret;
    } else if (componentAppId &&  componentAppSecret && getComponentTicket && getComponentToken && saveComponentToken) {
      this.componentApi = new ComponentAPI(componentAppId, componentAppSecret, getComponentTicket, getComponentToken, saveComponentToken)
      this.componentAppId = componentApi.componentAppId;
      this.componentAppSecret = componentApi.componentAppSecret;
    } else if (appId && appSecret) {
      this.appSecret = appSecret;
    } else {
      throw new Error('参数不完整');
    }
    this.appId = authorizerAppId || appId;
    this.tokenFromCustom = tokenFromCustom;
    this.ensureComponentToken = async function() {
      return await componentApi.ensureComponentToken();
    };
    this.getToken = getToken || async function () {
      return this.store;
    };
    this.saveToken = saveToken || async function (accessToken, refreshToken) {
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
  }

  /**
   * 用于设置urllib的默认options * Examples:
   * ```
   * api.setOpts({timeout: 15000});
   * ```
   * @param {Object} opts 默认选项
   */
  setOpts(opts) {
    this.defaults = opts;
  }

  /**
   * 设置urllib的hook
   */
  async request(url, opts, retry) {
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
    let res = await httpx.request(url, options);
    if (res.statusCode < 200 || res.statusCode > 204) {
      let err = new Error(`url: ${url}, status code: ${res.statusCode}`);
      err.name = 'WeChatAPIError';
      throw err;
    }

    let buffer = await httpx.read(res);
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

        if ((err.code === 40001 || err.code === 42001) && retry > 0 && !this.tokenFromCustom) {
          // 销毁已过期的token
          await this.saveToken(null);
          let token = await this.getAccessToken();
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
   * let token = await api.getAccessToken();
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
  async getAccessToken() {
    let url;
    let params;
    let { refreshToken } = await this.getToken();
    if (this.componentApi) {
      let componentAccessToken = await this.ensureComponentToken();
      url = `${this.prefix}component/api_authorizer_token?component_access_token=${componentAccessToken.componentAccessToken}`;
      params = {
        'component_appid': this.componentAppId,
        'authorizer_appid': this.appId,
        'authorizer_refresh_token': refreshToken
      };
    } else {
      url = `${this.prefix}token?grant_type=client_credential&appid=${this.appId}&secret=${this.appSecret}`;
      params = {};
    }
    
    let args = {
      method: 'post',
      data: JSON.stringify(params),
      dataType: 'json',
      contentType: 'json'
    };
    let data = await this.request(url, args);
    // 过期时间，因网络延迟等，将实际过期时间提前10秒，以防止临界点
    let expireTime = (new Date().getTime()) + (data.expires_in - 10) * 1000;
    let token = new AccessToken(data.authorizer_access_token || data.access_token, expireTime);
    await this.saveToken(token, data.authorizer_refresh_token || data.refresh_token);
    return token;
  }
  
  /*!
   * 需要access token的接口调用如果采用preRequest进行封装后，就可以直接调用。
   * 无需依赖 getAccessToken 为前置调用。
   * 应用开发者无需直接调用此API。
   * Examples:
   * ```
   * await api.ensureAccessToken();
   * ```
   */
  async ensureAccessToken() {
    // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
    let {accessToken} = await this.getToken();
    if (accessToken && (accessToken = new AccessToken(accessToken.accessToken, accessToken.expireTime)).isValid()) {
      return accessToken;
    } else if (this.tokenFromCustom) {
      let err = new Error('accessToken Error');
      err.name = 'WeChatAPIError';
      err.code = 40001;
      throw err;
    }
    return await this.getAccessToken();
  }
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
