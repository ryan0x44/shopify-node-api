import jwt from 'jsrsasign';

import {Context} from '../context';
import * as ShopifyErrors from '../error';

import validateShop from './shop-validator';

interface JwtPayload {
  iss: string;
  dest: string;
  aud: string;
  sub: string;
  exp: number;
  nbf: number;
  iat: number;
  jti: string;
  sid: string;
}

/**
 * Decodes the given session token, and extracts the session information from it
 *
 * @param token Received session token
 */
function decodeSessionToken(token: string): JwtPayload {
  let payload: object;
  try {
    if (jwt.KJUR.jws.JWS.verifyJWT(token, Context.API_SECRET_KEY, { alg: ['HS256']}) === false) {
      throw new Error("unable to verify against API secret key")
    };
    const parsed = jwt.KJUR.jws.JWS.parse(token)
    if (parsed.payloadObj == null) {
      throw new  Error("unable to parse JWT payload")
    }
    payload = parsed.payloadObj
  } catch (error) {
    throw new ShopifyErrors.InvalidJwtError(`Failed to parse session token '${token}': ${error.message}`);
  }

  // The exp and nbf fields are validated by the JWT library

  if (payload.aud !== Context.API_KEY) {
    throw new ShopifyErrors.InvalidJwtError('Session token had invalid API key');
  }

  if (!validateShop(payload.dest.replace(/^https:\/\//, ''))) {
    throw new ShopifyErrors.InvalidJwtError('Session token had invalid shop');
  }

  return payload;
}

export default decodeSessionToken;

export {
  decodeSessionToken,
  JwtPayload,
};
