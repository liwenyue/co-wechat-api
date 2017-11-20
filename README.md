Wechat API(ES6版)
===========
微信公共平台API。

## 模块状态
- [![NPM version](https://badge.fury.io/js/co-wechat-open-api.png)](http://badge.fury.io/js/co-wechat-open-api)

## 功能列表
- 发送客服消息（文本、图片、语音、视频、音乐、图文）
- 菜单操作（查询、创建、删除、个性化菜单）
- 二维码（创建临时、永久二维码，查看二维码URL）
- 分组操作（查询、创建、修改、移动用户到分组）
- 用户信息（查询用户基本信息、获取关注者列表）
- 媒体文件（上传、获取）
- 群发消息（文本、图片、语音、视频、图文）
- 客服记录（查询客服记录，查看客服、查看在线客服）
- 群发消息
- 公众号支付（发货通知、订单查询）
- 微信小店（商品管理、库存管理、邮费模板管理、分组管理、货架管理、订单管理、功能接口）
- 模版消息
- 网址缩短
- 语义查询
- 数据分析
- JSSDK服务端支持
- 素材管理
- 摇一摇周边

## Installation

```sh
$ npm install co-wechat-open-api@1.0.4
```

## Usage

```js
const api = new WeChatOpenApi(config.open.appId, config.open.appSecret, appId, null,
  function *() {
    // 获取ComponentVerifyTicket   
  },
  function *(){
    //获取 componentAccessToken
  },
  function *(token) {
    //保存 componentAccessToken
  },
  function *(){
    // 获取公众号授权后,调用api需要的 accessToken 和 refreshToken  返回 object {accessToken: {accessToken: 'accessToken', expiredAt: ''}, refreshToken: 'refreshToken'}
  },
  function *(accessToken, refreshToken) {
    //获取公众号授权后,调用api需要的accessToken 和 refreshToken
  },
  function *(openid){
    //获取单个用户授权的accessToken 里面包含了 refreshToken
  },
  function *(openid, accessToken) {
    //保存单个用户授权的accessToken 里面包含了 refreshToken
  });
  
function*getTicketToken() {
  // 获取Js Ticket
}

function*saveTicketToken(token) {
  //保存Js Ticket
}

api.registerTicketHandle(getTicketToken, saveTicketToken);

```

## License
The MIT license.
