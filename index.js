'use strict'

const { Strategy } = require('passport-strategy')
const util = require('util')
const axios = require('axios')
const boom = require('@hapi/boom')

/**
 * `AuthServiceStrategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function AuthServiceStrategy (options = {}, verify = false) {
  Strategy.call(this)

  if (!options.serviceUrl) throw new Error('Auth field serviceUr is required')

  this._serviceUrl = options.serviceUrl
  this.name = 'AuthService'
  this._realm = options.realm || 'Users'
  this._passReqToCallback = options.passReqToCallback
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(AuthServiceStrategy, Strategy)

/**
 * Authenticate request based on the contents of a HTTP Basic authorization
 *
 * @param {Object} req
 * @api protected
 */
AuthServiceStrategy.prototype.authenticate = async function (req) {
  const authorization = req.headers.authorization
  if (!authorization) return this.fail(this._challenge())

  const parts = authorization.split(' ')
  if (parts.length < 2) return this.fail(400)

  const scheme = parts[0]
  const jwt = parts[1]

  if (!/Bearer/i.test(scheme)) return this.fail(this._challenge())
  if (!jwt) return this.fail(400)

  const self = this

  try {
    const { data } = await axios.get(`${this._serviceUrl}/auth/tokens/${jwt}`)
    const tokenInfo = data.data

    if (!tokenInfo.isValid) throw boom.unauthorized(`Error, ${tokenInfo.message}`)

    self.success(tokenInfo)
  } catch (error) {
    if (error) return self.error(error)
  }
}

/**
 * Authentication challenge.
 *
 * @api private
 */
AuthServiceStrategy.prototype._challenge = function () {
  return 'Basic realm="' + this._realm + '"'
}

module.exports = AuthServiceStrategy
