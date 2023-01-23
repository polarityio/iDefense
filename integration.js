'use strict';

const request = require('postman-request');
const _ = require('lodash');
const async = require('async');
const config = require('./config/config');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const BASE_URI = 'https://api.intelgraph.idefense.com/rest/fundamental/v0/';

function _setupRegexBlocklists (options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function doLookup (entities, options, cb) {
  let lookupResults = [];

  _setupRegexBlocklists(options);

  async.each(
    entities,
    function (entityObj, next) {
      if (_isEntityBlocklisted(entityObj, options)) {
        next(null);
      } else {
        _lookupEntity(entityObj, options, function (err, result) {
          if (err) {
            next(err);
          } else {
            lookupResults.push(result);
            next(null);
          }
        });
      }
    },
    function (err) {
      cb(err, lookupResults);
    }
  );
}

function _isEntityBlocklisted (entityObj, options) {
  const blocklist = options.blocklist;

  Logger.debug({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entityObj.value.toLowerCase())) {
    return true;
  }

  if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ ip: entityObj.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entityObj.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entityObj.value)) {
        Logger.debug({ domain: entityObj.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }
  return false;
}

function _getUrl (entityObj, options) {
  let entityType = null;
  let query = null;
  let entityValue = entityObj.value.toLowerCase();
  // map entity object type to the IRIS REST API type
  switch (entityObj.type) {
    case 'domain':
      entityType = 'domain';
      query = 'key.query';
      entityValue = `"${entityValue}"`; // domain must be quoted to ensure exact matches
      break;
    case 'IPv4':
      entityType = 'ip';
      query = 'key.values';
      break;
    case 'email':
      entityType = 'phish';
      query = 'sender.query';
      entityValue = `"${entityValue}"`; // email must be quoted to ensure exact matches
      break;
    case 'hash':
      entityType = 'file';
      query = 'key.values';
      break;
    case 'custom':
      if (entityObj.types.indexOf('custom.cve') >= 0) {
        entityType = 'vulnerability';
        query = 'key.values';
        entityValue = entityObj.value.toUpperCase(); // CVE must be in uppercase to get results
      } else {
        entityType = '';
        query = 'key.values';
        entityValue = `cpe:/${entityObj.value.toLowerCase()}`;
      }
      break;
    case 'url':
      entityType = 'url';
      query = 'key.query';
      entityValue = `"${entityValue}"`;
      break;
  }
  let request = {
    uri: `${BASE_URI}${entityType}`,
    qs: {
      page_size: options.pageSize,
      'severity.from': options.minScore.value
    }
  };

  request.qs[query] = entityValue;

  return request;
}

function _getRequestOptions (entityObj, options) {
  let request = _getUrl(entityObj, options);

  return {
    uri: request.uri,
    headers: { 'auth-token': options.apiKey },
    qs: request.qs,
    method: 'GET',
    json: true
  };
}

function _lookupEntity (entityObj, options, cb) {
  const requestOptions = _getRequestOptions(entityObj, options);

  Logger.debug({ options: requestOptions }, 'Checking the request options coming through');
  let url = null;

  if (entityObj.type === 'IPv4') {
    url = 'https://intelgraph.idefense.com/#/node/ip/view/';
  } else if (entityObj.type === 'domain') {
    url = 'https://intelgraph.idefense.com/#/node/domain/view/';
  } else if (entityObj.type === 'url') {
    url = 'https://intelgraph.idefense.com/#/node/url/view/';
  } else if (entityObj.type === 'hash') {
    url = 'https://intelgraph.idefense.com/#/node/file/view/';
  } else if (entityObj.type === 'email') {
    url = 'https://intelgraph.idefense.com/#/node/phish/view/';
  } else if (entityObj.types.indexOf('custom.cve') >= 0) {
    url = 'https://intelgraph.idefense.com/#/node/vulnerability/view/';
  } else {
    url = 'https://intelgraph.idefense.com/#/node/cpe/view/';
  }

  requestWithDefaults(requestOptions, function (err, response, body) {
    let errorObject = _isApiError(err, response, body, entityObj.value);
    if (errorObject) {
      cb(errorObject);
      return;
    }

    if (_isLookupMiss(response, body)) {
      return cb(null, {
        entity: entityObj,
        data: null
      });
    }

    Logger.trace({ body: body, entity: entityObj.value }, 'HTTP Request Body');

    if (_.isNull(body) || _.isEmpty(body) || body.total_size === 0) {
      cb(null, {
        entity: entityObj,
        data: null // this entity will be cached as a miss
      });
      return;
    }

    // The lookup results returned is an array of lookup objects with the following format
    cb(null, {
      // Required: This is the entity object passed into the integration doLookup method
      entity: entityObj,
      // Required: An object containing everything you want passed to the template
      data: {
        // Required: These are the tags that are displayed in your template
        summary: [],
        // Data that you want to pass back to the notification window details block
        details: {
          body: body,
          url: url
        }
      }
    });
  });
}

function _isLookupMiss (response, body) {
  return (
    response.statusCode === 404 ||
    response.statusCode === 400 ||
    response.statusCode === 503 ||
    response.statusCode === 300 ||
    response.statusCode === 500 ||
    typeof body === 'undefined'
  );
}

function _isApiError (err, response, body, entityValue) {
  if (err) {
    return {
      detail: 'Error executing HTTP request',
      error: err
    };
  }

  // Any code that is not 200 and not 404 (missed response) or 400, we treat as an error
  if (
    response.statusCode !== 200 &&
    response.statusCode !== 404 &&
    response.statusCode !== 400 &&
    response.statusCode !== 503 &&
    response.statusCode !== 300 &&
    response.statusCode !== 500
  ) {
    return _createJsonErrorPayload(
      'Unexpected HTTP Status Code',
      null,
      response.statusCode,
      '1',
      'Unexpected HTTP Status Code',
      {
        err: err,
        body: body,
        entityValue: entityValue
      }
    );
  } else if (response.statusCode === 500) {
    return _createJsonErrorPayload(
      'Error with ApiKey',
      null,
      response.statusCode,
      '1',
      'ApiKey is incorrect, please contact iDefense for correct key.',
      {
        err: err,
        body: body,
        entityValue: entityValue
      }
    );
  }

  return null;
}

function validateOptions (userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide an iDefense API key'
    });
  }

  if (typeof userOptions.domainBlocklistRegex.value === 'string' && userOptions.domainBlocklistRegex.value.length > 0) {
    try {
      new RegExp(userOptions.domainBlocklistRegex.value);
    } catch (error) {
      errors.push({
        key: 'domainBlocklistRegex',
        message: error.toString()
      });
    }
  }

  if (typeof userOptions.ipBlocklistRegex.value === 'string' && userOptions.ipBlocklistRegex.value.length > 0) {
    try {
      new RegExp(userOptions.ipBlocklistRegex.value);
    } catch (e) {
      errors.push({
        key: 'ipBlocklistRegex',
        message: error.toString()
      });
    }
  }

  cb(null, errors);
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload (msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

// function that creates the Json object to be passed to the payload
function _createJsonErrorObject (msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'iDef_' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

function startup (logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
