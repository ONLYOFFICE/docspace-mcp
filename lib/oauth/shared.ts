/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

/**
 * @module
 * @mergeModuleWith oauth
 */

/* eslint-disable unicorn/prefer-top-level-await */

import z from "zod"

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7515#section-4.1 | RFC 7515 Reference}
 */
export const JwsHeaderSchema = z.
	object({
		"alg": z.string(),
		"jku": z.string().optional(),
		"jwk": z.string().optional(),
		"kid": z.string().optional(),
		"x5u": z.union([z.string(), z.array(z.string())]).optional(),
		"x5c": z.union([z.string(), z.array(z.string())]).optional(),
		"x5t": z.string().optional(),
		"x5t#S256": z.string().optional(),
		"typ": z.string().optional(),
		"cty": z.string().optional(),
		"crit": z.union([z.string(), z.array(z.string())]).optional(),
	}).
	passthrough()

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7519#section-4 | RFC 7519 Reference}
 */
export const JwtClaimsSchema = z.
	object({
		iss: z.string().optional(),
		sub: z.string().optional(),
		aud: z.union([z.string(), z.array(z.string())]).optional(),
		exp: z.number().optional(),
		nbf: z.number().optional(),
		iat: z.number().optional(),
		jti: z.string().optional(),
	}).
	passthrough()

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1 | RFC 6749 Reference}
 */
export const AuthorizeRequestSchema = z.object({
	response_type: z.literal("code"),
	client_id: z.string(),
	redirect_uri: z.string().optional(),
	scope: z.string().optional(),
	state: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7662#section-2.1 | RFC 7662 Reference}
 */
export const IntrospectRequestSchema = z.object({
	token: z.string(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7009#section-2.1 | RFC 7009 Reference}
 */
export const RevokeRequestSchema = z.object({
	token: z.string().optional(),
	token_type_hint: z.union([z.literal("access_token"), z.literal("refresh_token")]).optional().catch(undefined),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1 | RFC 6749 Reference #1}\
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3 | RFC 6749 Reference #2}
 */
export const AccessTokenRequestSchema = z.object({
	grant_type: z.literal("authorization_code"),
	code: z.string(),
	redirect_uri: z.string().optional(),
	client_id: z.string(),
	client_secret: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-6 | RFC 6749 Reference}
 */
export const RefreshTokenRequestSchema = z.object({
	grant_type: z.literal("refresh_token"),
	refresh_token: z.string(),
	scope: z.array(z.string()).optional(),
})

export const TokenRequestSchema = z.union([
	AccessTokenRequestSchema,
	RefreshTokenRequestSchema,
])

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-5.2 | RFC 6749 Reference}
 */
export const ErrorResponseSchema = z.object({
	error: z.string(),
	error_description: z.string().optional(),
	error_uri: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc8414#section-3.2 | RFC 8414 Reference}
 */
export const ServerMetadataResponseSchema = z.object({
	issuer: z.string(),
	authorization_endpoint: z.string().optional(),
	token_endpoint: z.string().optional(),
	registration_endpoint: z.string().optional(),
	response_types_supported: z.array(z.string()),
	grant_types_supported: z.array(z.string()).optional(),
	token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	revocation_endpoint: z.string().optional(),
	revocation_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	introspection_endpoint: z.string().optional(),
	introspection_endpoint_auth_methods_supported: z.array(z.string()).optional(),
	code_challenge_methods_supported: z.array(z.string()).optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc9728#name-protected-resource-metadata-r | RFC 9728 Reference}
 */
export const ResourceMetadataResponseSchema = z.object({
	resource: z.string(),
	authorization_servers: z.array(z.string()).optional(),
	bearer_methods_supported: z.array(z.string()).optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2 | RFC 6749 Reference}
 */
export const AuthorizeResponseSchema = z.object({
	code: z.string(),
	state: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7662#section-2.2 | RFC 7662 Reference}
 */
export const IntrospectResponseSchema = z.object({
	active: z.boolean(),
	scope: z.string().optional(),
	client_id: z.string().optional(),
	username: z.string().optional(),
	token_type: z.string().optional(),
	exp: z.number().optional(),
	iat: z.number().optional(),
	nbf: z.number().optional(),
	sub: z.string().optional(),
	aud: z.union([z.string(), z.array(z.string())]).optional(),
	iss: z.string().optional(),
	jti: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1 | RFC 7591 Reference}
 */
export const RegisterResponseSchema = z.object({
	client_id: z.string(),
	client_secret: z.string().optional(),
})

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-5.1 | RFC 6749 Reference}
 */
export const TokenResponseSchema = z.object({
	access_token: z.string(),
	token_type: z.string(),
	expires_in: z.number().optional(),
	refresh_token: z.string().optional(),
	scope: z.string().optional(),
})

export type JwtHeader = z.infer<typeof JwsHeaderSchema>

export type AuthorizeRequest = z.infer<typeof AuthorizeRequestSchema>

export type IntrospectRequest = z.infer<typeof IntrospectRequestSchema>

export type RevokeRequest = z.infer<typeof RevokeRequestSchema>

export type AccessTokenRequest = z.infer<typeof AccessTokenRequestSchema>

export type RefreshTokenRequest = z.infer<typeof RefreshTokenRequestSchema>

export type TokenRequest = z.infer<typeof TokenRequestSchema>

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>

export type ServerMetadataResponse = z.infer<typeof ServerMetadataResponseSchema>

export type ResourceMetadataResponse = z.infer<typeof ResourceMetadataResponseSchema>

export type AuthorizeResponse = z.infer<typeof AuthorizeResponseSchema>

export type IntrospectResponse = z.infer<typeof IntrospectResponseSchema>

export type RegisterResponse = z.infer<typeof RegisterResponseSchema>

export type TokenResponse = z.infer<typeof TokenResponseSchema>
