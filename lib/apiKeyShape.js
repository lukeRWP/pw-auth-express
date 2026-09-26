'use strict';
// pwiam API keys look like pwk_<16-hex keyId>_<43-char base64url secret> (32 random bytes, unpadded).
// Shared by requireApiKey, the instance-level introspectApiKey and the standalone apiKeyVerifier so
// the format can't drift between them: anything that doesn't match is rejected before it ever costs
// a network call or a cache entry.
const API_KEY_SHAPE = /^pwk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;

const isValidApiKeyShape = (key) => typeof key === 'string' && API_KEY_SHAPE.test(key);

module.exports = { API_KEY_SHAPE, isValidApiKeyShape };
