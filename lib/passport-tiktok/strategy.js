'use strict'

const TIKTOK_STRATEGY_PREFIX = '[passport-tiktok-basic]'

var isFunction = require('lodash/isFunction'),
  isObjectLike = require('lodash/isObjectLike'),
  isString = require('lodash/isString'),
  isUndefined = require('lodash/isUndefined'),
  util = require('util'),
  OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
  InternalOAuthError = require('passport-oauth').InternalOAuthError

const fetchConfig = {
  RETRY_COUNT: 2,
  RETRY_SLEEP_MS: 500,
  TIMEOUT_MS: 3000,
}

var _fetch = require('node-fetch')

/**
 * Returns username from profile url.
 * @param {string} url - Shortened URL profile
 * @return {string | undefined}
 */
function getUsernameFromProfileUrl(url) {
  if (typeof url !== 'string') {
    return undefined
  }
  
  // remove query params
  const [urlPart] = url.split('?')
  
  const usernameMatch = urlPart.match(/\/@([^/]+)$/)
  
  if (!usernameMatch) {
    return undefined
  }
  
  return usernameMatch[1]
}

/**
 * @param {number} ms
 * @return {Promise<unknown>}
 */
const sleep = async (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** @type {_fetch} */
const fetchProxy = async (url, config) => {
  const retries = config?.retries ?? 0
  
  try {
    const response = await _fetch(url, config)
    if (!response.ok) {
      if (retries > 0) {
        await sleep(fetchConfig.RETRY_SLEEP_MS)
        return fetchProxy(url, {
          ...config,
          retries: retries - 1,
        })
      }
    }
    
    return response
  } catch (err) {
    console.info(TIKTOK_STRATEGY_PREFIX, config)
    console.error(TIKTOK_STRATEGY_PREFIX, err)
    
    if (retries > 0) {
      await sleep(fetchConfig.RETRY_SLEEP_MS)
      return fetchProxy(url, {
        ...config,
        retries: retries - 1,
      })
    }
    
    throw err
  }
}

/**
 * `Strategy` constructor.
 *
 * The Tiktok authentication strategy authenticates requests by delegating
 * to Tiktok using the OAuth 2.0 protocol as described here:
 * https://developers.tiktok.com/doc/login-kit-web
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`         your Tiktok application's app id
 *   - `clientSecret`      your Tiktok application's app secret
 *   - `scope`              Scopes allowed for your Tiktok Application
 *   - `callbackURL`        URL to which Tiktok will redirect the user after granting authorization
 *
 * Examples:
 *
 *     var tiktok = require('passport-tiktok');
 *
 *     passport.use(new tiktok.Strategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         scope: ['user.info.basic'],
 *         callbackURL: 'https://www.example.net/auth/tiktok/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  
  if (!isObjectLike(options)) {
    throw new TypeError('Please pass the options.')
  }
  
  if (!isFunction(verify)) {
    throw new TypeError('Please pass the verify callback.')
  }
  
  function validateStringOption(optionName) {
    if (!isUndefined(options[optionName]) && (!isString(options[optionName]) || options[optionName].length === 0)) {
      throw new TypeError('Please pass a string to options.' + optionName)
    }
  }
  
  validateStringOption('authorizationURL')
  validateStringOption('tokenURL')
  validateStringOption('scopeSeparator')
  validateStringOption('sessionKey')
  validateStringOption('profileURL')
  
  options.authorizationURL = options.authorizationURL || 'https://www.tiktok.com/v2/auth/authorize/'
  options.tokenURL = options.tokenURL || 'https://open.tiktokapis.com/v2/oauth/token/'
  options.scopeSeparator = options.scopeSeparator || ','
  options.scope = "user.info.basic"
  options.sessionKey = options.sessionKey || 'oauth2:tiktok'
  
  OAuth2Strategy.call(this, options, verify)
  this.name = 'tiktok'
  this._oauth2.useAuthorizationHeaderforGET(true)
  this._profileURL = options.profileURL || 'https://open.tiktokapis.com/v2/user/info/'
  this.options = options
  
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy)

/**
 * Retrieve user profile from Tiktok.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `tiktok`
 *   - `id`               the user's internal Tiktok ID
 *   - `displayName`      the user's full name
 *   - `url`              the user's profile page url
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, authData, done) {
  const self = this
  var url = this._profileURL
  const params = {
    fields: ['avatar_url_100', 'display_name','open_id','union_id','display_name']
  }

  const parsedParams = new URLSearchParams(params).toString();
  console.log(`fetch url ${url}?${parsedParams}`);
  return fetchProxy(`${url}?${parsedParams}`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
    retries: fetchConfig.RETRY_COUNT,
    timeout: fetchConfig.TIMEOUT_MS,
  }).then((userInfoResponse) => {
    try {
      return userInfoResponse.json()
        .then((userInfo) => {
          console.log("user info",userInfo);
          var user = userInfo.data.user;
          
           
            console.log("profile response");
            // var profileUrl = profileLinkResponse
            // var username = getUsernameFromProfileUrl(profileUrl)
            
            // if (!username) {
            //   console.info(TIKTOK_STRATEGY_PREFIX, user)
            //   console.info(TIKTOK_STRATEGY_PREFIX, profileLinkResponse.url)
            //   done(new Error('Failed to extract username from profile link'))
            // }
            
            try {
              var profile = {
                username: user.display_name.toLowerCase().replaceAll(' ',''),
                provider: 'tiktok',
                id: user.open_id,
                unionId: user.union_id,
                profileImage: user.avatar_url_100,
                displayName: user.display_name,
              }
            } catch(e) {
              console.log("profile object error",e);
            }
            // console.log("Profile",profile)
            profile._raw = JSON.stringify(userInfo)
            profile._json = userInfo
            
            done(null, profile)
          
          // .catch(err => {
          //   console.log(TIKTOK_STRATEGY_PREFIX, err)
          //   console.log(TIKTOK_STRATEGY_PREFIX, userInfo)
          //   done(new Error('Sorry, this service is currently unavailable',err))
          // })
        }).catch((err) => {
          console.error(TIKTOK_STRATEGY_PREFIX, err)
          console.error(TIKTOK_STRATEGY_PREFIX, userInfoResponse)
          done(new Error('Sorry, this service is currently unavailable'))
        })
    } catch (e) {
      // Failed to get profile
      console.info(TIKTOK_STRATEGY_PREFIX, 'Failed to get profile')
      console.error(TIKTOK_STRATEGY_PREFIX, e)
      done(e)
    }
  }).catch((err) => {
    return done(new InternalOAuthError('failed to fetch user profile', err))
  })
}

/**
 * Return extra Tiktok-specific parameters to be included in the
 * authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  return { client_key: this.options.clientID }
}

/**
 * Return extra Tiktok-specific parameters to be included in the
 * authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.tokenParams = function (options) {
  return { client_key: this.options.clientID, client_secret: this.options.clientSecret }
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  var self = this
  
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description })
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri))
    }
  }
  
  var callbackURL = options.callbackURL || this._callbackURL
  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId,
    callbackURL: callbackURL,
  }
  
  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) {
        return self.error(err)
      }
      if (!ok) {
        return self.fail(state, 403)
      }
      
      var code = req.query.code
      
      var params = self.tokenParams(options)
      params.grant_type = 'authorization_code'
      if (callbackURL) {
        params.redirect_uri = callbackURL
      }
      if (typeof ok == 'string') { // PKCE
        params.code_verifier = ok
      }
      params.code = code
      console.info(TIKTOK_STRATEGY_PREFIX, 'request for tokens')
      
      /**
       * @param {*} data
       * @return {boolean}
       */
      function isSuccessTokenResponse(data) {
        return data.access_token && data.refresh_token
      }
      
      return fetchProxy(self.options.tokenURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(params),
        retries: fetchConfig.RETRY_COUNT,
        timeout: fetchConfig.TIMEOUT_MS,
      }).then((data) => {
        return data.json().then((tokens) => {
          if (!isSuccessTokenResponse(tokens)) {
            return self.error(self._createOAuthError('Failed to obtain access token', params.data))
          }
          
          const {
            access_token: accessToken,
            refresh_token: refreshToken,
          } = tokens
          
          self._loadUserProfile(accessToken, tokens, function (err, profile) {
            if (err) {
              return self.error(err)
            }
            
            function verified(err, user, info) {
              if (err) {
                return self.error(err)
              }
              if (!user) {
                return self.fail(info)
              }
              
              info = info || {}
              if (state) {
                info.state = state
              }
              self.success(user, info)
            }
            
            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, tokens, profile, verified)
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified)
                }
              } else {
                var arity = self._verify.length
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, tokens, profile, verified)
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified)
                }
              }
            } catch (ex) {
              return self.error(ex)
            }
          })
        }).catch((err) => {
          console.error(err)
          return self.error(new Error('Failed to obtain tokens'))
        })
      })
    }
    
    var state = req.query.state
    try {
      var arity = self._stateStore.verify.length
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded)
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded)
      }
    } catch (ex) {
      return this.error(ex)
    }
  } else {
    return OAuth2Strategy.prototype.authenticate.call(this, req, options)
  }
}

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function (accessToken, paramsData, done) {
  var self = this
  
  function loadIt() {
    return self.userProfile(accessToken, paramsData, done)
  }
  
  function skipIt() {
    return done(null)
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function (err, skip) {
      if (err) {
        return done(err)
      }
      if (!skip) {
        return loadIt()
      }
      return skipIt()
    })
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile
    if (!skip) {
      return loadIt()
    }
    return skipIt()
  }
}
/**
 * Expose `Strategy`.
 */
module.exports = Strategy
