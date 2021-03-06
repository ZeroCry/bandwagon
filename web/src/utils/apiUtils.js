/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import $ from 'jquery';
import localStorage from './storageUtils';

const ajaxDefaultCfg = {
  contentType: 'application/json; charset=utf-8',
  dataType: 'json',
  cache: false,
  beforeSend: xhr => setAuthHeaders(xhr)
}

let apiUtils = {

  renewToken(){
    return this.ajax({
      type: 'POST',
      url: '/proxy/v1/webapi/sessions/renew'
    })
  },

  post(data){
    let cfg = {
      url: 'api/complete',
      type: 'POST',
      data: JSON.stringify(data)
    };

    return this.ajax(cfg);
  },

  init() {
    let cfg = {
      url: 'api/info',
      type: 'GET'
    }

    return this.ajax(cfg).then(createInfo);
  },

  ajax(cfg){
    return $.ajax($.extend({}, ajaxDefaultCfg, cfg));
  },

  logout(){
    window.location = '/web/login';
  },

  getErrorText(err){
    let msg = 'Unknown error';

    if (err instanceof Error) {
      return err.message || msg;
    }

    if(err.responseJSON && err.responseJSON.message){
      return err.responseJSON.message;
    }

    if (err.responseJSON && err.responseJSON.error) {
      return err.responseJSON.error.message || msg;
    }

    if (err.responseText) {
      return err.responseText;
    }

    return msg;
  }
}

function setAuthHeaders(xhr) {
  const bearerToken = localStorage.getBearerToken() || {};
  xhr.setRequestHeader('Authorization', 'Bearer ' + bearerToken.accessToken);
}

function createInfo(json){
  const { app={}, remoteSupportConfigured } = json;
  const name = app.displayName || app.name;
  const application = {
    name: name || 'Application',
    version: app.version,
    remoteSupportConfigured
  };

  return { application };
}


export default apiUtils;
