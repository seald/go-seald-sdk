import crypto from 'node:crypto'
import fetch from 'node-fetch'
import { SignJWT } from 'jose'
import { promisify } from 'node:util'

const randomBytes = promisify(crypto.randomBytes)

const B64toS64 = (data) => data
  .replace(/\//g, '%')
  .replace(/=/g, '')

export const b64UUID = (UUID) => {
  UUID = UUID.toLowerCase().replace(/-/g, '')
  return B64toS64(Buffer.from(UUID, 'hex').toString('base64'))
}

export const randomString = (length = 10) => {
  const bytes = crypto.randomBytes(length)
  const str = bytes.toString('hex')
  return str.slice(0, length)
}

export const TMRBackend = (keyStorageURL, appId, appKey) => ({
  async challengeSend (userId, authFactor, { createUser = false, forceAuth = false } = {}) {
    const url = new URL('/tmr/back/challenge_send/', keyStorageURL).href
    const res = await fetch(
      url,
      {
        method: 'POST',
        credentials: 'omit',
        headers: {
          'Content-Type': 'application/json',
          'X-SEALD-APPID': appId,
          'X-SEALD-APIKEY': appKey
        },
        body: JSON.stringify({
          user_id: userId,
          auth_factor: authFactor,
          create_user: createUser,
          force_auth: forceAuth,
          template: '<html><body>TEST CHALLENGE EMAIL</body></html>'
        })
      }
    )
    if (!res.ok) {
      console.error('Error in SSKSBackend createUser:', res.status, await res.text())
      throw new Error('Error in SSKSBackend createUser')
    }
    const { session_id: sessionId, must_authenticate: mustAuthenticate } = await res.json()
    return { sessionId, mustAuthenticate }
  }
})

const random = async (length = 16) => {
  const buff = await randomBytes(Math.ceil(length / 2))
  return buff.toString('hex')
}

const createJWT = async (secret, data) => {
  const token = new SignJWT(data)
    .setProtectedHeader({ alg: 'HS256' })

  return token.sign(Buffer.from(secret, 'ascii'))
}

export const generateRegistrationJWT = async (JWTSecretId, JWTSecret) => createJWT(JWTSecret, {
  iss: JWTSecretId,
  jti: await random(16),
  iat: Math.floor(Date.now() / 1000),
  scopes: [3], // PERMISSION_JOIN_TEAM
  join_team: true
})
