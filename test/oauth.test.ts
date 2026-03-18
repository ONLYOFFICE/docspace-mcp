/**
 * @module test
 */

import assert from "node:assert/strict"
import http from "node:http"
import type net from "node:net"
import test from "node:test"
import jwt from "jsonwebtoken"
import * as meta from "../lib/meta.ts"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupBinOptions} from "./util.ts"
import {
	Deferred,
	inDelta,
	isUuid,
	onRequest,
	parseFetchLocation,
	randomAddress,
	readFetchJson,
	readFetchText,
	readHttpForm,
	readHttpJson,
	sendJson,
	setupBin,
	setupHttp,
} from "./util.ts"

// todo: client.ts
// upstream can respond with invalid JSON

// todo: errors
// some error_descriptions have broken tabulation
// some error_descriptions are not informative

// todo: req.method, req.url

async function setup(t: test.TestContext, e: object): Promise<net.AddressInfo> {
	let a = await randomAddress()
	assert.ok(a.err === undefined)

	let o: SetupBinOptions = {
		host: a.v.address,
		port: a.v.port,
		env: {
			DOCSPACE_TRANSPORT: "http",
			DOCSPACE_HOST: a.v.address,
			DOCSPACE_PORT: `${a.v.port}`,
			DOCSPACE_OAUTH_BASE_URL: "http://localhost/",
			DOCSPACE_SERVER_ALLOWED_HOSTNAMES: `[${a.v.address}]`,
			DOCSPACE_SERVER_BASE_URL: `http://[${a.v.address}]:${a.v.port}/`,
			DOCSPACE_REQUEST_QUERY: "0", // todo: questionable
			DOCSPACE_REQUEST_AUTHORIZATION_HEADER: "",
			DOCSPACE_REQUEST_HEADER_PREFIX: "",
			...e,
		},
	}

	await setupBin(t, o)

	return a.v
}

function withAuth(fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		if (!(input instanceof URL)) {
			throw new Error("Input is not URL")
		}

		if (!init) {
			throw new Error("Init is missing")
		}

		if (init.headers) {
			if (Array.isArray(init.headers) || init.headers instanceof Headers) {
				throw new Error("Headers are not object")
			}

			init.headers = {...init.headers}
		} else {
			init.headers = {}
		}

		let s = ""

		for (let c of "basic") {
			if (Math.random() < 0.5) {
				s += c.toLowerCase()
			} else {
				s += c.toUpperCase()
			}
		}

		let p = Buffer.from("xxx:yyy").toString("base64")

		init.headers.Authorization = `${s} ${p}`

		return await fetch(input, init)
	}
}

async function sendAccessToken(_: Parameters<http.RequestListener>[0], res: Parameters<http.RequestListener>[1]): Promise<string> {
	let o: jwt.SignOptions = {
		algorithm: "none",
	}

	let t = r.safeSync(jwt.sign, {}, "", o)
	assert.ok(t.err === undefined)

	let b: object = {
		access_token: t.v,
		token_type: "test",
	}

	let s = await sendJson(res, 200, b)
	assert.ok(s.err === undefined)

	return t.v
}

async function requestAccessToken(a: net.AddressInfo): Promise<string> {
	let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
	assert.ok(u.err === undefined)

	let f = new URLSearchParams()

	f.set("grant_type", "authorization_code")
	f.set("code", "vvv")

	let i: RequestInit = {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: f.toString(),
	}

	let fetch = withAuth(globalThis.fetch)

	let res = await r.safeAsync(fetch, u.v, i)
	assert.ok(res.err === undefined)

	assert.ok(res.v.status === 200)

	let b = await readFetchJson(res.v)
	assert.ok(b.err === undefined)

	assert.ok(b.v && typeof b.v === "object")
	assert.ok("access_token" in b.v && typeof b.v.access_token === "string")

	return b.v.access_token
}

async function requestState(a: net.AddressInfo, q: URLSearchParams): Promise<string> {
	let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
	assert.ok(u.err === undefined)

	let p = new URLSearchParams()

	p.set("response_type", "code")
	p.set("client_id", "xxx")
	p.set("redirect_uri", "http://localhost:8030")

	for (let [k, v] of q.entries()) {
		p.set(k, v)
	}

	u.v.search = p.toString()

	let i: RequestInit = {
		redirect: "manual",
	}

	let res = await r.safeAsync(fetch, u.v, i)
	assert.ok(res.err === undefined)

	assert.ok(res.v.status === 302)

	let l = parseFetchLocation(res.v)
	assert.ok(l.err === undefined)

	let s = l.v.searchParams.get("state")
	assert.ok(s)

	return s
}

function checkJwtAlg(t: string, alg: jwt.Algorithm, k: string): void {
	if (alg === "none") {
		let o: jwt.DecodeOptions = {
			complete: true,
		}

		let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

		let j = decode(t, o)
		assert.ok(j)

		let h: object = {
			alg,
			typ: "JWT",
		}

		assert.deepEqual(j.header, h)

		assert.ok(j.signature.length === 0)
	} else {
		let o: jwt.VerifyOptions = {
			algorithms: [alg],
			complete: true,
			ignoreExpiration: true,
			ignoreNotBefore: true,
		}

		let verify = jwt.verify as (t: string, k: string, o: jwt.VerifyOptions) => jwt.Jwt

		let j = r.safeSync(verify, t, k, o)
		assert.ok(j.err === undefined)

		let h: object = {
			alg,
			typ: "JWT",
		}

		assert.deepEqual(j.v.header, h)

		assert.ok(j.v.signature.length !== 0)
	}
}

function checkJwtTtl(t: string, ttl: number): void {
	let o: jwt.DecodeOptions = {
		complete: true,
	}

	let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

	let j = decode(t, o)
	assert.ok(j)

	assert.ok(typeof j.payload === "object")

	let now = Date.now()

	if (ttl) {
		assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now + ttl, 3000))
	} else {
		assert.ok(!("exp" in j.payload))
	}

	assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
	assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
}

function checkJwtPayload(t: string, p: object): void {
	let o: jwt.DecodeOptions = {
		complete: true,
	}

	let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

	let j = decode(t, o)
	assert.ok(j)

	assert.partialDeepStrictEqual(j.payload, p)
}

type TestAllowedHostnamesOptions = {
	env: object
	method: string
	path: string
}

function testAllowedHostnames(o: TestAllowedHostnamesOptions): void {
	let request = async(a: net.AddressInfo, h: string): Promise<http.IncomingMessage> => {
		let headers: Record<string, string> = {
			Host: h,
		}

		if (o.method === "POST") {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
			headers["Content-Length"] = "0"
		}

		let ro: http.RequestOptions = {
			headers,
			host: a.address,
			method: o.method,
			path: o.path,
			port: a.port,
			setHost: false,
		}

		let p = new Promise<r.Result<http.IncomingMessage, Error>>((resolve) => {
			let req = http.request(ro, (res) => {
				resolve(r.ok(res))
			})

			req.on("error", (err) => {
				resolve(r.error(err))
			})

			req.end()
		})

		let w = await p
		assert.ok(w.err === undefined)

		return w.v
	}

	let ta: string[] = [
		"localhost",
		"127.0.0.1",
		"[::1]",
	]

	void test.suite("allowed hostnames", () => {
		void test.suite("allows request with default allowed hostnames", () => {
			for (let tt of ta) {
				void test(tt, async(t) => {
					let e: object = {
						...o.env,
						DOCSPACE_SERVER_ALLOWED_HOSTNAMES: undefined,
					}

					let a = await setup(t, e)

					let res = await request(a, tt)

					assert.ok(res.statusCode !== 403)
				})
			}
		})

		void test.suite("allows request when Host matches custom allowed hostname", () => {
			for (let tt of ta) {
				void test(tt, async(t) => {
					let e: object = {
						...o.env,
						DOCSPACE_SERVER_ALLOWED_HOSTNAMES: tt,
					}

					let a = await setup(t, e)

					let res = await request(a, tt)

					assert.ok(res.statusCode !== 403)
				})
			}
		})

		void test.suite("allows request when Host matches one of multiple allowed hostnames", () => {
			for (let tt of ta) {
				void test(tt, async(t) => {
					let e: object = {
						...o.env,
						DOCSPACE_SERVER_ALLOWED_HOSTNAMES: ta.join(","),
					}

					let a = await setup(t, e)

					let res = await request(a, tt)

					assert.ok(res.statusCode !== 403)
				})
			}
		})

		void test.suite("allows request when Host includes port with allowed hostname", () => {
			for (let tt of ta) {
				void test(tt, async(t) => {
					let e: object = {
						...o.env,
						DOCSPACE_SERVER_ALLOWED_HOSTNAMES: tt,
					}

					let a = await setup(t, e)

					let res = await request(a, `${tt}:8080`)

					assert.ok(res.statusCode !== 403)
				})
			}
		})

		void test("allows any request when allowed hostnames list is empty", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_ALLOWED_HOSTNAMES: "",
			}

			let a = await setup(t, e)

			let res = await request(a, "evil.com")

			assert.ok(res.statusCode !== 403)
		})

		void test("blocks request when Host header is missing", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_ALLOWED_HOSTNAMES: "localhost",
			}

			let a = await setup(t, e)

			let res = await request(a, "")

			assert.ok(res.statusCode === 403)

			let ab = await readHttpJson(res)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Host header is missing",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("blocks request with malformed Host header", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_ALLOWED_HOSTNAMES: "localhost",
			}

			let a = await setup(t, e)

			let res = await request(a, "invalid host")

			assert.ok(res.statusCode === 403)

			let ab = await readHttpJson(res)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Parsing Host header\n" +
					"\tInvalid URL",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("blocks request when Host not in allowed list", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_ALLOWED_HOSTNAMES: "localhost",
			}

			let a = await setup(t, e)

			let res = await request(a, "evil.com")

			assert.ok(res.statusCode === 403)

			let ab = await readHttpJson(res)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Hostname evil.com is not allowed",
			}

			assert.deepEqual(ab.v, eb)
		})
	})
}

type TestCorsOptions = {
	env: object
	method: string
	path: string
}

function testCors(o: TestCorsOptions): void {
	let check = (res: Response, ha: [string, string[]][]): void => {
		assert.ok(res.status === 204)

		for (let [k, v] of ha) {
			let h = res.headers.get(k)
			assert.ok(h)

			let a = h.split(",")

			for (let i = 0; i < a.length; i += 1) {
				a[i] = a[i].trim()
			}

			for (let e of v) {
				assert.ok(a.includes(e))
			}
		}
	}

	void test.suite("cors", () => {
		let wh: [string, string[]][] = [
			["Access-Control-Allow-Origin", ["*"]],
			["Access-Control-Max-Age", ["86400"]],
			["Content-Length", ["0"]],
		]

		if (o.path.startsWith("/.well-known")) {
			wh.push(["Access-Control-Allow-Methods", ["GET"]])
			wh.push(["Vary", ["Access-Control-Request-Headers"]])
		} else if (o.path.startsWith("/oauth")) {
			wh.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
			wh.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
			wh.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
		}

		void test("allows any origin by default", async(t) => {
			let a = await setup(t, o.env)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, wh)
		})

		void test("allows any origin when explicitly set to wildcard", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "*",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, wh)
		})

		void test("allows any origin when wildcard is in origin list", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "*,http://localhost",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, wh)

			i = {
				method: "OPTIONS",
				headers: {
					Origin: "http://localhost",
				},
			}

			res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, wh)
		})

		let rh: [string, string[]][] = [
			["Access-Control-Max-Age", ["86400"]],
			["Content-Length", ["0"]],
		]

		if (o.path.startsWith("/.well-known")) {
			rh.push(["Access-Control-Allow-Methods", ["GET"]])
			rh.push(["Vary", ["Origin", "Access-Control-Request-Headers"]])
		} else if (o.path.startsWith("/oauth")) {
			rh.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
			rh.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
			rh.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
			rh.push(["Vary", ["Origin"]])
		}

		void test("allows single configured origin", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "http://localhost",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, rh)

			i = {
				method: "OPTIONS",
				headers: {
					Origin: "http://localhost",
				},
			}

			res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, rh)

			assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost")
		})

		void test("allows multiple configured origins", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "http://localhost:8001,http://localhost:8002",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, rh)

			i = {
				method: "OPTIONS",
				headers: {
					Origin: "http://localhost:8001",
				},
			}

			res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, rh)

			assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost:8001")

			i = {
				method: "OPTIONS",
				headers: {
					Origin: "http://localhost:8002",
				},
			}

			res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, rh)

			assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost:8002")
		})

		let ca: [string, string[]][] = [
			["Access-Control-Allow-Origin", ["*"]],
			["Access-Control-Max-Age", ["3600"]],
			["Content-Length", ["0"]],
		]

		if (o.path.startsWith("/.well-known")) {
			ca.push(["Access-Control-Allow-Methods", ["GET"]])
			ca.push(["Vary", ["Access-Control-Request-Headers"]])
		} else if (o.path.startsWith("/oauth")) {
			ca.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
			ca.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
			ca.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
		}

		void test("respects custom max age setting", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_MAX_AGE: "3600000",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			check(res.v, ca)
		})

		void test("returns error for OPTIONS preflight when cors is disabled", async(t) => {
			let e: object = {
				...o.env,
				DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "OPTIONS",
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status !== 204)

			assert.ok(res.v.headers.get("Allow") === o.method)
		})
	})
}

type TestMethodNotAllowedOptions = {
	env: object
	path: string
	allowed: string
}

function testMethodNotAllowed(o: TestMethodNotAllowedOptions): void {
	void test.suite("method not allowed", () => {
		let ta: string[] = [
			"DELETE",
			"GET",
			"PATCH",
			"POST",
			"PUT",
		]

		for (let tt of ta) {
			if (tt !== o.allowed) {
				void test(`method ${tt} not allowed`, async(t) => {
					let a = await setup(t, o.env)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let i: RequestInit = {
						method: tt,
					}

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 405)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						error: "invalid_request",
						error_description: "Method Not Allowed",
					}

					assert.deepEqual(ab.v, eb)
				})
			}
		}
	})
}

type TestUnsupportedMediaTypeOptions = {
	env: object
	method: string
	path: string
}

function testUnsupportedMediaType(o: TestUnsupportedMediaTypeOptions): void {
	let check = async(res: Response): Promise<void> => {
		assert.ok(res.status === 415)

		let ab = await readFetchJson(res)
		assert.ok(ab.err === undefined)

		let eb: object = {
			error: "invalid_request",
			error_description: "Unsupported Media Type",
		}

		assert.deepEqual(ab.v, eb)
	}

	void test.suite("unsupported media type", () => {
		void test("rejects request with unsupported Content-Type header", async(t) => {
			let a = await setup(t, o.env)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: o.method,
				headers: {
					"Content-Type": "application/text",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			await check(res.v)
		})

		void test("rejects request without Content-Type header", async(t) => {
			let a = await setup(t, o.env)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: o.method,
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			await check(res.v)
		})
	})
}

type TestRateLimitOptions = {
	env: object
	method: string
	path: string
	contentType: string
	defaultCapacity: number
	defaultWindow: number
	capacityEnv: string
	windowEnv: string
}

function testRateLimit(o: TestRateLimitOptions): void {
	let request = async(a: net.AddressInfo): Promise<Response> => {
		let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
		assert.ok(u.err === undefined)

		let i: RequestInit = {
			method: o.method,
		}

		if (o.contentType) {
			i.headers = {
				"Content-Type": o.contentType,
			}
		}

		let res = await r.safeAsync(fetch, u.v, i)
		assert.ok(res.err === undefined)

		return res.v
	}

	type checkOptions = {
		limit: string | null
		policy: string | null
		remaining: string | null
		reset: string | null
		after: string | null
	}

	let check = (h: Headers, o: checkOptions): void => {
		let eh = h.get("Access-Control-Expose-Headers")
		assert.ok(eh)

		let aa = eh.split(",")

		let ea: string[] = [
			"RateLimit-Limit",
			"RateLimit-Policy",
			"RateLimit-Remaining",
			"RateLimit-Reset",
			"Retry-After",
		]

		for (let h of ea) {
			assert.ok(aa.includes(h))
		}

		assert.ok(h.get("RateLimit-Limit") === o.limit)
		assert.ok(h.get("RateLimit-Policy") === o.policy)
		assert.ok(h.get("RateLimit-Remaining") === o.remaining)
		assert.ok(h.get("RateLimit-Reset") === o.reset)
		assert.ok(h.get("Retry-After") === o.after)
	}

	void test.suite("rate limit", () => {
		void test("applies default rate limit headers", async(t) => {
			let a = await setup(t, o.env)

			let res = await request(a)

			let co: checkOptions = {
				limit: `${o.defaultCapacity}`,
				policy: `${o.defaultCapacity};w=${o.defaultWindow / 1000}`,
				remaining: `${o.defaultCapacity - 1}`,
				reset: `${o.defaultWindow / 1000}`,
				after: null,
			}

			check(res.headers, co)
		})

		void test("applies custom rate limit headers", async(t) => {
			let e: object = {
				...o.env,
				[o.capacityEnv]: "100",
				[o.windowEnv]: "30000",
			}

			let a = await setup(t, e)

			let res = await request(a)

			let co: checkOptions = {
				limit: "100",
				policy: "100;w=30",
				remaining: "99",
				reset: "30",
				after: null,
			}

			check(res.headers, co)
		})

		void test("omits rate limit headers when disabled", async(t) => {
			let e: object = {
				...o.env,
				[o.capacityEnv]: "0",
				[o.windowEnv]: "0",
			}

			let a = await setup(t, e)

			let res = await request(a)

			let co: checkOptions = {
				limit: null,
				policy: null,
				remaining: null,
				reset: null,
				after: null,
			}

			check(res.headers, co)
		})

		void test("blocks request after exceeding rate limit", async(t) => {
			let e: object = {
				...o.env,
				[o.capacityEnv]: "1",
				[o.windowEnv]: "60000",
			}

			let a = await setup(t, e)

			let res = await request(a)

			let co: checkOptions = {
				limit: "1",
				policy: "1;w=60",
				remaining: "0",
				reset: "60",
				after: null,
			}

			check(res.headers, co)

			res = await request(a)

			co = {
				limit: "1",
				policy: "1;w=60",
				remaining: "0",
				reset: "60",
				after: "60",
			}

			assert.ok(res.status === 429)

			check(res.headers, co)

			let ab = await readFetchJson(res)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "too_many_requests",
				error_description: "Too Many Requests",
			}

			assert.deepEqual(ab.v, eb)
		})
	})
}

type TestClientAuthErrorHandlingOptions = {
	path: string
}

function testClientAuthErrorHandling(o: TestClientAuthErrorHandlingOptions): void {
	void test.suite("client authentication error handling", () => {
		void test("returns error when Authorization header is malformed", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": "v",
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Parsing header\n" +
					"\tMalformed header",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when Authorization header has invalid scheme", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": "v v",
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Parsing header\n" +
					"\tInvalid scheme",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when Authorization header has malformed password", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": "Basic v",
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Parsing header\n" +
					"\tMalformed password",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when Authorization header is missing client_id", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let p = Buffer.from(":").toString("base64")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": `Basic ${p}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Parsing header\n" +
					"\tNo client_id",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when Authorization header is missing client_secret", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let p = Buffer.from("xxx:").toString("base64")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": `Basic ${p}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Parsing header\n" +
					"\tNo client_secret",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when both Authorization header and client_id in body provided", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let p = Buffer.from("xxx:yyy").toString("base64")

			let f = new URLSearchParams()

			f.set("client_id", "xxx")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": `Basic ${p}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: f.toString(),
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 400)

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Multiple authentication methods",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when both Authorization header and client_secret in body provided", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let p = Buffer.from("xxx:yyy").toString("base64")

			let f = new URLSearchParams()

			f.set("client_secret", "yyy")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": `Basic ${p}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: f.toString(),
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 400)

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Multiple authentication methods",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when both Authorization header and client credentials in body provided", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let p = Buffer.from("xxx:yyy").toString("base64")

			let f = new URLSearchParams()

			f.set("client_id", "xxx")
			f.set("client_secret", "yyy")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Authorization": `Basic ${p}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: f.toString(),
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 400)

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Multiple authentication methods",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when client_id is missing from body with environment credentials configured", async(t) => {
			let e: object = {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 400)

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Parsing body\n" +
					"\t\tclient_id: invalid_type Invalid input: expected string, received undefined",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when client_id in body mismatches environment credentials", async(t) => {
			let e: object = {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			}

			let a = await setup(t, e)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let f = new URLSearchParams()

			f.set("client_id", "zzz")

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: f.toString(),
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 401)

			assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_client",
				error_description: "Client ID mismatch",
			}

			assert.deepEqual(ab.v, eb)
		})

		void test("returns error when client credentials are missing from body", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.status === 400)

			let ab = await readFetchJson(res.v)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Parsing body\n" +
					"\t\tclient_id: invalid_type Invalid input: expected string, received undefined\n" +
					"\t\tclient_secret: invalid_type Invalid input: expected string, received undefined",
			}

			assert.deepEqual(ab.v, eb)
		})
	})
}

type TestClientAuthOptions = {
	skipCredentials: boolean
	path: string
	body: Record<string, string>
}

function testClientAuth(o: TestClientAuthOptions): void {
	let listener = (): AsyncRequestListener => {
		return async(req, res) => {
			if (!o.skipCredentials) {
				let ab = await readHttpForm(req)
				assert.ok(ab.err === undefined)

				let eb: object = {
					client_id: "xxx",
					client_secret: "yyy",
				}

				assert.partialDeepStrictEqual(ab.v, eb)
			}

			res.end()
		}
	}

	void test.suite("client authentication", () => {
		void test("authenticates client via Authorization header", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn(listener())

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from("xxx:yyy").toString("base64")

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `BaSiC ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("authenticates client via client_id in body when configured in environment", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn(listener())

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("client_id", "xxx")

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("authenticates client via client_id and client_secret in body when configured in environment", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn(listener())

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("client_id", "xxx")
				f.set("client_secret", "yyy")

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("authenticates client via client_id and client_secret in body", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn(listener())

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("client_id", "xxx")
				f.set("client_secret", "yyy")

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})
	})
}

type TestUserAgentOptions = {
	path: string
	body: Record<string, string>
}

function testUserAgent(o: TestUserAgentOptions): void {
	void test.suite("user agent", () => {
		void test("uses default User-Agent", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
				assert.ok(req.headers["user-agent"] === `${meta.name} v${meta.version}`)

				res.end()
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("uses custom User-Agent", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
				assert.ok(req.headers["user-agent"] === "test")

				res.end()
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_USER_AGENT: "test",
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})
	})
}

type TestAbortPropagationOptions = {
	path: string
	body: Record<string, string>
}

function testAbortPropagation(o: TestAbortPropagationOptions): void {
	void test.suite("abort propagation", () => {
		void test("aborts upstream request when client disconnects", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let rd = new Deferred()
			rd.withTimeout(3000, "Timeout waiting for upstream to receive request")

			let cd = new Deferred()
			cd.withTimeout(3000, "Timeout waiting for upstream to detect close")

			t.after(() => {
				rd.clear()
				cd.clear()
			})

			let hl: AsyncRequestListener = async(req) => {
				rd.resolve()
				req.on("close", cd.resolve.bind(cd))
				await cd.promise
			}

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let ac = new AbortController()

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
					signal: ac.signal,
				}

				let fetch = withAuth(globalThis.fetch)

				let p = r.safeAsync(fetch, u.v, i)

				await rd.promise

				ac.abort()

				await cd.promise

				let res = await p
				assert.ok(res.err !== undefined)
			}

			await Promise.race([hp, tf()])
		})
	})
}

type TestProxyHeaderForwardingOptions = {
	path: string
	body: Record<string, string>
}

function testProxyHeaderForwarding(o: TestProxyHeaderForwardingOptions): void {
	void test.suite("proxy header forwarding", () => {
		void test("sets X-Forwarded-For and X-Real-IP from client IP", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
				assert.ok(req.headers["x-forwarded-for"] === "::1")
				assert.ok(req.headers["x-real-ip"] === "::1")

				res.end()
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("extends X-Forwarded-For preserving X-Real-IP", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
				assert.ok(req.headers["x-forwarded-for"] === "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348, ::1")
				assert.ok(req.headers["x-real-ip"] === "203.0.113.190")

				res.end()
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						"X-Forwarded-For": "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
						"X-Real-IP": "203.0.113.190",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})
	})
}

type TestProxyErrorHandlingOptions = {
	path: string
	body: Record<string, string>
}

function testProxyErrorHandling(o: TestProxyErrorHandlingOptions): void {
	void test.suite("proxy error handling", () => {
		void test("passes through upstream error response", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, async(_, res) => {
				let b: object = {
					error: "some_error",
					error_description: "some_description",
					error_uri: "some_uri",
				}

				let s = await sendJson(res, 418, b)
				assert.ok(s.err === undefined)
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 418)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "some_error",
					error_description: "some_description",
					error_uri: "some_uri",
				}

				assert.deepEqual(ab.v, eb)
			}

			await Promise.race([hp, tf()])
		})

		void test("transforms upstream custom error to protocol error", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, async(_, res) => {
				let b: object = {
					reason: "some_reason",
				}

				let s = await sendJson(res, 418, b)
				assert.ok(s.err === undefined)
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 418)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "server_error",
					error_description: "some_reason",
				}

				assert.deepEqual(ab.v, eb)
			}

			await Promise.race([hp, tf()])
		})

		void test("returns error when upstream responds without Content-Type header", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, (_, res) => {
				res.statusCode = 418
				res.end()
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 418)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "server_error",
					error_description: "Content-Type is missing",
				}

				assert.deepEqual(ab.v, eb)
			}

			await Promise.race([hp, tf()])
		})

		void test("returns error when upstream responds with invalid Content-Type header", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, (_, res) => {
				res.statusCode = 418
				res.setHeader("Content-Type", "text/plain")
				res.end()
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 418)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "server_error",
					error_description: "Content-Type is invalid",
				}

				assert.deepEqual(ab.v, eb)
			}

			await Promise.race([hp, tf()])
		})
	})
}

type TestRequestIdReflectionOptions = {
	method: string
	path: string
}

function testRequestIdReflection(o: TestRequestIdReflectionOptions): void {
	void test.suite("request id reflection", () => {
		void test("reflects X-Request-ID back to client when provided", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let id = "12345678-1234-1234-1234-123456789abc"

			let i: RequestInit = {
				method: o.method,
				headers: {
					"X-Request-ID": id,
				},
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			assert.ok(res.v.headers.get("X-Request-ID") === id)
		})

		void test("generates X-Request-ID and reflects it in response when not provided", async(t) => {
			let a = await setup(t, {})

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: o.method,
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			let id = res.v.headers.get("X-Request-ID")
			assert.ok(id && isUuid(id))
		})
	})
}

type TestRequestIdForwardingOptions = {
	path: string
	body: Record<string, string>
}

function testRequestIdForwarding(o: TestRequestIdForwardingOptions): void {
	void test.suite("request id forwarding", () => {
		void test("forwards X-Request-ID from client request to upstream", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let id = "12345678-1234-1234-1234-123456789abc"

			let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
				assert.ok(req.headers["x-request-id"] === id)

				let s = await sendJson(res, 200, {})
				assert.ok(s.err === undefined)
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						"X-Request-ID": id,
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})

		void test("generates X-Request-ID and forwards it to upstream when not provided", async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
				let id = req.headers["x-request-id"]
				assert.ok(typeof id === "string" && isUuid(id))

				let s = await sendJson(res, 200, {})
				assert.ok(s.err === undefined)
			})

			let hp = onRequest(t, hs, hl)

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				for (let [k, v] of Object.entries(o.body)) {
					f.set(k, v)
				}

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)
			}

			await Promise.race([hp, tf()])

			assert.ok(hl.mock.callCount() === 1)
		})
	})
}

void test.suite("oauth server", async() => {
	let ot = ""
	let wt = ""

	await (async() => {
		let f = async(t: test.TestContext): Promise<void> => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, async(_, res) => {
				ot = await sendAccessToken(_, res)
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				wt = await requestAccessToken(a)
			}

			await Promise.race([hp, tf()])
		}

		let errs: Error[] = []

		let a: test.TestContextHookFn[] = []

		let t = {
			after(cb) {
				if (cb) {
					a.push(cb)
				}
			},
		} as test.TestContext

		let w = await r.safeAsync(f, t)
		if (w.err) {
			errs.push(new Error("Calling test", {cause: w.err}))
		}

		for (let cb of a) {
			let w = await r.safeAsync(cb, t, () => {})
			if (w.err) {
				errs.push(new Error("Calling hook", {cause: w.err}))
			}
		}

		if (errs.length !== 0) {
			throw new AggregateError(errs, "Executing test")
		}
	})()

	void test.suite("/.well-known/oauth-authorization-server", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestRateLimitOptions &
			TestRequestIdReflectionOptions

		let o: Options = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-authorization-server",
			allowed: "GET",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_WINDOW",
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testRateLimit(o)
		testRequestIdReflection(o)

		void test.suite("server metadata", () => {
			void test("returns server metadata without dynamic client registration", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/.well-known/oauth-authorization-server", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					issuer: `http://[${a.address}]:${a.port}`,
					authorization_endpoint: `http://[${a.address}]:${a.port}/oauth/authorize`,
					token_endpoint: `http://[${a.address}]:${a.port}/oauth/token`,
					response_types_supported: [
						"code",
					],
					grant_types_supported: [
						"authorization_code",
						"refresh_token",
					],
					token_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					revocation_endpoint: `http://[${a.address}]:${a.port}/oauth/revoke`,
					revocation_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					introspection_endpoint: `http://[${a.address}]:${a.port}/oauth/introspect`,
					introspection_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					code_challenge_methods_supported: [
						"S256",
					],
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns server metadata with dynamic client registration", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/.well-known/oauth-authorization-server", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					issuer: `http://[${a.address}]:${a.port}`,
					authorization_endpoint: `http://[${a.address}]:${a.port}/oauth/authorize`,
					token_endpoint: `http://[${a.address}]:${a.port}/oauth/token`,
					registration_endpoint: `http://[${a.address}]:${a.port}/oauth/register`,
					response_types_supported: [
						"code",
					],
					grant_types_supported: [
						"authorization_code",
						"refresh_token",
					],
					token_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					revocation_endpoint: `http://[${a.address}]:${a.port}/oauth/revoke`,
					revocation_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					introspection_endpoint: `http://[${a.address}]:${a.port}/oauth/introspect`,
					introspection_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					code_challenge_methods_supported: [
						"S256",
					],
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	})

	void test.suite("/.well-known/oauth-protected-resource", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestRateLimitOptions &
			TestRequestIdReflectionOptions

		let o: Options = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-protected-resource",
			allowed: "GET",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_WINDOW",
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testRateLimit(o)
		testRequestIdReflection(o)

		void test.suite("resource metadata", () => {
			void test("returns resource metadata", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/.well-known/oauth-protected-resource", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					resource: `http://[${a.address}]:${a.port}`,
					authorization_servers: [
						`http://[${a.address}]:${a.port}/oauth/authorize`,
					],
					bearer_methods_supported: [
						"header",
					],
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	})

	void test.suite("/oauth/authorize", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestRateLimitOptions &
			TestRequestIdReflectionOptions

		let o: Options = {
			env: {},
			method: "GET",
			path: "/oauth/authorize",
			allowed: "GET",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_WINDOW",
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testRateLimit(o)
		testRequestIdReflection(o)

		void test.suite("error handling", () => {
			void test("returns error when query parameters are missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						'\t\tresponse_type: invalid_value Invalid input: expected "code"\n' +
						"\t\tclient_id: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when response_type is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "invalid")
				q.set("client_id", "xxx")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						'\t\tresponse_type: invalid_value Invalid input: expected "code"',
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when redirect_uri is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "code")
				q.set("client_id", "xxx")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "No redirect URI",
				}

				assert.deepEqual(ab.v, eb)
			})
		})

		void test.suite("redirect", () => {
			void test("redirects to upstream", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "code")
				q.set("client_id", "xxx")
				q.set("redirect_uri", "http://localhost:8030")

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8020/oauth2/authorize")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: object = {
					client_id: "xxx",
					redirect_uri: `http://[${a.address}]:${a.port}/oauth/callback`,
					response_type: "code",
					state: aq.state,
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})
		})

		void test.suite("state token signature algorithm", () => {
			void test("signs state token with HS256 algorithm by default", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "yyy",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtAlg(s, "HS256", "yyy")
			})

			let ta: jwt.Algorithm[] = [
				"HS256",
				"HS384",
				"HS512",
			]

			for (let tt of ta) {
				void test(`signs state token with ${tt} algorithm`, async(t) => {
					let e: object = {
						DOCSPACE_OAUTH_STATE_TOKEN_ALGORITHM: tt,
						DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "yyy",
					}

					let a = await setup(t, e)

					let q = new URLSearchParams()

					let s = await requestState(a, q)

					checkJwtAlg(s, tt, "yyy")
				})
			}

			void test("signs state token without signature when algorithm is disabled", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_ALGORITHM: "",
					DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtAlg(s, "none", "")
			})
		})

		void test.suite("state token expiration time", () => {
			void test("sets default state token expiration", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 3600000)
			})

			void test("sets custom state token expiration", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_TTL: 1800000,
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 1800000)
			})

			void test("creates state token without expiration when ttl is disabled", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_TTL: 0,
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 0)
			})
		})

		void test.suite("state token payload", () => {
			void test("embeds redirect_uri in state token payload", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8040")

				let s = await requestState(a, q)

				let p: object = {
					redirect_uri: "http://localhost:8040",
				}

				checkJwtPayload(s, p)
			})

			void test("embeds client state in state token payload", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				q.set("state", "data")

				let s = await requestState(a, q)

				let p: object = {
					state: "data",
				}

				checkJwtPayload(s, p)
			})
		})
	})

	void test.suite("/oauth/callback", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestRateLimitOptions &
			TestRequestIdReflectionOptions

		let o: Options = {
			env: {},
			method: "GET",
			path: "/oauth/callback",
			allowed: "GET",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_CALLBACK_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_CALLBACK_WINDOW",
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testRateLimit(o)
		testRequestIdReflection(o)

		void test.suite("error handling", () => {
			void test("returns error when query parameters are missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						"\t\tcode: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when state parameter is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("code", "vvv")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "No state",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when state token is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", "www")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Verifying token\n" +
						"\tVerifying token\n" +
						"\t\tjwt malformed",
				}

				assert.deepEqual(ab.v, eb)
			})
		})

		void test.suite("redirect", () => {
			void test("redirects to upstream preserving client state", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8030/app")
				q.set("state", "data")

				let s = await requestState(a, q)

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", s)

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8030/app")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: Record<string, string> = {
					code: "vvv",
					state: "data",
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})

			void test("redirects to upstream without preserving client state", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8030/app")

				let s = await requestState(a, q)

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", s)

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8030/app")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: Record<string, string> = {
					code: "vvv",
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})
		})
	})

	void test.suite("/oauth/introspect", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestUnsupportedMediaTypeOptions &
			TestRateLimitOptions &
			TestClientAuthErrorHandlingOptions &
			TestClientAuthOptions &
			TestUserAgentOptions &
			TestAbortPropagationOptions &
			TestProxyHeaderForwardingOptions &
			TestProxyErrorHandlingOptions &
			TestRequestIdReflectionOptions &
			TestRequestIdForwardingOptions

		let o: Options = {
			env: {},
			method: "POST",
			path: "/oauth/introspect",
			allowed: "POST",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_INTROSPECT_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_INTROSPECT_WINDOW",
			skipCredentials: true,
			body: {
				get token() {
					return wt
				},
			},
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testUnsupportedMediaType(o)
		testRateLimit(o)
		testClientAuthErrorHandling(o)
		testClientAuth(o)
		testUserAgent(o)
		testAbortPropagation(o)
		testProxyHeaderForwarding(o)
		testProxyErrorHandling(o)
		testRequestIdReflection(o)
		testRequestIdForwarding(o)

		void test.suite("error handling", () => {
			void test("returns error when token parameter is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\ttoken: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when token is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", "zzz")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_token",
					error_description: "Verifying token\n" +
						"\tVerifying token\n" +
						"\t\tjwt malformed",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", wt)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Introspecting token\n" +
					"\tMaking request\n" +
					"\t\tMaking bare request\n" +
					"\t\t\tMaking native request\n" +
					"\t\t\t\tfetch failed\n" +
					"\t\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})
		})

		void test.suite("token forwarding", () => {
			void test("unwraps and forwards original token to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: ot,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("token", wt)

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})

		void test.suite("introspection response", () => {
			let requestIntrospection = async(a: net.AddressInfo, t: string): Promise<object> => {
				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", t)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let b = await readFetchJson(res.v)
				assert.ok(b.err === undefined)

				assert.ok(b.v && typeof b.v === "object")

				return b.v
			}

			let checkExpiration = (b: object, ttl: number): void => {
				assert.ok("exp" in b && typeof b.exp === "number")

				let now = Date.now()

				assert.ok(inDelta(b.exp * 1000, now + ttl, 3000))
			}

			void test("returns inactive status for expired token", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						exp: Math.floor((now - 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void test("returns inactive status for not-yet-valid token", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void test("returns active from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let b: object = {
							active: false,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void test("uses minimum expiration when both token and upstream have expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0: {
						let now = Date.now()

						let p: jwt.JwtPayload = {
							exp: Math.floor((now + 3600000) / 1000),
						}

						let o: jwt.SignOptions = {
							algorithm: "none",
						}

						let t = r.safeSync(jwt.sign, p, "", o)
						assert.ok(t.err === undefined)

						let b: object = {
							access_token: t.v,
							token_type: "test",
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					case 1: {
						let now = Date.now()

						let b: object = {
							active: true,
							exp: Math.floor((now + 7200000) / 1000),
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void test("uses upstream expiration when token has no expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let now = Date.now()

						let b: object = {
							active: true,
							exp: Math.floor((now + 7200000) / 1000),
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 7200000)
				}

				await Promise.race([hp, tf()])
			})

			void test("uses token expiration when upstream has no expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0: {
						let now = Date.now()

						let p: jwt.JwtPayload = {
							exp: Math.floor((now + 3600000) / 1000),
						}

						let o: jwt.SignOptions = {
							algorithm: "none",
						}

						let t = r.safeSync(jwt.sign, p, "", o)
						assert.ok(t.err === undefined)

						let b: object = {
							access_token: t.v,
							token_type: "test",
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					case 1: {
						let b: object = {
							active: true,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void test("omits expiration when neither token nor upstream have expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let b: object = {
							active: true,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: true,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})
		})
	})

	void test.suite("/oauth/register", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestUnsupportedMediaTypeOptions &
			TestRateLimitOptions &
			TestRequestIdReflectionOptions

		let o: Options = {
			env: {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			},
			method: "POST",
			path: "/oauth/register",
			allowed: "POST",
			contentType: "application/json",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REGISTER_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REGISTER_WINDOW",
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testUnsupportedMediaType(o)
		testRateLimit(o)
		testRequestIdReflection(o)

		void test.suite("endpoint availability", () => {
			void test("returns 404 when dynamic client registration is not enabled", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 404)
			})
		})

		void test.suite("registration response", () => {
			void test("returns client_id", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 201)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					client_id: "xxx",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("echoes request body", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let ob: object = {
					test: "test",
				}

				let sb = r.safeSync(JSON.stringify, ob, null, 2)
				assert.ok(sb.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: sb.v,
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 201)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					test: "test",
				}

				assert.partialDeepStrictEqual(ab.v, eb)
			})
		})
	})

	void test.suite("/oauth/revoke", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestUnsupportedMediaTypeOptions &
			TestRateLimitOptions &
			TestClientAuthErrorHandlingOptions &
			TestClientAuthOptions &
			TestUserAgentOptions &
			TestAbortPropagationOptions &
			TestProxyHeaderForwardingOptions &
			TestProxyErrorHandlingOptions &
			TestRequestIdReflectionOptions &
			TestRequestIdForwardingOptions

		let o: Options = {
			env: {},
			method: "POST",
			path: "/oauth/revoke",
			allowed: "POST",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REVOKE_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REVOKE_WINDOW",
			skipCredentials: false,
			body: {
				token: "vvv",
			},
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testUnsupportedMediaType(o)
		testRateLimit(o)
		testClientAuthErrorHandling(o)
		testClientAuth(o)
		testUserAgent(o)
		testAbortPropagation(o)
		testProxyHeaderForwarding(o)
		testProxyErrorHandling(o)
		testRequestIdReflection(o)
		testRequestIdForwarding(o)

		void test.suite("error handling", () => {
			void test("returns error when token parameter is missing", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\ttoken: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", "vvv")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Revoking token\n" +
					"\tMaking bare request\n" +
					"\t\tMaking native request\n" +
					"\t\t\tfetch failed\n" +
					"\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})
		})

		void test.suite("token handling", () => {
			let requestRevocation = async(a: net.AddressInfo, f: URLSearchParams): Promise<void> => {
				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)
			}

			void test("unwraps and forwards original token to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: ot,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let hf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let f = new URLSearchParams()

					f.set("token", wt)

					await requestRevocation(a, f)
				}

				await Promise.race([hp, hf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void test("forwards non-wrapped token as-is to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: "vvv",
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let hf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let f = new URLSearchParams()

					f.set("token", "vvv")

					await requestRevocation(a, f)
				}

				await Promise.race([hp, hf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			let ta: string[] = [
				"access_token",
				"refresh_token",
			]

			for (let tt of ta) {
				// eslint-disable-next-line typescript/no-loop-func
				void test(`forwards token_type_hint ${tt} when provided`, async(t) => {
					let [hs, ha] = await setupHttp(t)

					let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
						let ab = await readHttpForm(req)
						assert.ok(ab.err === undefined)

						let eb: object = {
							token_type_hint: tt,
						}

						assert.partialDeepStrictEqual(ab.v, eb)

						res.end()
					})

					let hp = onRequest(t, hs, hl)

					let hf = async(): Promise<void> => {
						let e: object = {
							DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						}

						let a = await setup(t, e)

						let f = new URLSearchParams()

						f.set("token", wt)
						f.set("token_type_hint", tt)

						await requestRevocation(a, f)
					}

					await Promise.race([hp, hf()])

					assert.ok(hl.mock.callCount() === 1)
				})
			}
		})
	})

	void test.suite("/oauth/token", () => {
		type Options =
			TestAllowedHostnamesOptions &
			TestCorsOptions &
			TestMethodNotAllowedOptions &
			TestUnsupportedMediaTypeOptions &
			TestRateLimitOptions &
			TestClientAuthErrorHandlingOptions &
			TestClientAuthOptions &
			TestUserAgentOptions &
			TestAbortPropagationOptions &
			TestProxyHeaderForwardingOptions &
			TestProxyErrorHandlingOptions &
			TestRequestIdReflectionOptions &
			TestRequestIdForwardingOptions

		let o: Options = {
			env: {},
			method: "POST",
			path: "/oauth/token",
			allowed: "POST",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_TOKEN_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_TOKEN_WINDOW",
			skipCredentials: false,
			body: {
				grant_type: "authorization_code",
				code: "vvv",
			},
		}

		testAllowedHostnames(o)
		testCors(o)
		testMethodNotAllowed(o)
		testUnsupportedMediaType(o)
		testRateLimit(o)
		testClientAuthErrorHandling(o)
		testClientAuth(o)
		testUserAgent(o)
		testAbortPropagation(o)
		testProxyHeaderForwarding(o)
		testProxyErrorHandling(o)
		testRequestIdReflection(o)
		testRequestIdForwarding(o)

		void test.suite("error handling", () => {
			void test("returns error when grant_type is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when code is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "authorization_code")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when refresh_token is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "refresh_token")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "authorization_code")
				f.set("code", "vvv")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Requesting token\n" +
					"\tMaking request\n" +
					"\t\tMaking bare request\n" +
					"\t\t\tMaking native request\n" +
					"\t\t\t\tfetch failed\n" +
					"\t\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})

			void test("returns error when upstream returns invalid token type", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let b: object = {
						access_token: "invalid",
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 500)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						error: "server_error",
						error_description: "Encoding token\n" +
							"\tInvalid token",
					}

					assert.deepEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})
		})

		void test.suite("upstream request parameters", () => {
			void test("forwards authorization code grant to upstream", async(t) => {
				let sa: net.AddressInfo | undefined

				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					assert.ok(sa)

					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						grant_type: "authorization_code",
						code: "vvv",
						redirect_uri: `http://[${sa.address}]:${sa.port}/oauth/callback`,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					sa = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${sa.address}]:${sa.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void test("forwards refresh token grant to upstream ", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						grant_type: "refresh_token",
						refresh_token: "zzz",
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "refresh_token")
					f.set("refresh_token", "zzz")
					f.set("scope", "test")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})

		void test.suite("auth token signature algorithm", () => {
			void test("signs auth token with HS256 algorithm by default", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "zzz",
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtAlg(s, "HS256", "zzz")
				}

				await Promise.race([hp, tf()])
			})

			let ta: jwt.Algorithm[] = [
				"HS256",
				"HS384",
				"HS512",
			]

			for (let tt of ta) {
				void test(`signs auth token with ${tt} algorithm`, async(t) => {
					let [hs, ha] = await setupHttp(t)

					let hp = onRequest(t, hs, async(_, res) => {
						await sendAccessToken(_, res)
					})

					let tf = async(): Promise<void> => {
						let e: object = {
							DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
							DOCSPACE_OAUTH_AUTH_TOKEN_ALGORITHM: tt,
							DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "zzz",
						}

						let a = await setup(t, e)

						let s = await requestAccessToken(a)

						checkJwtAlg(s, tt, "zzz")
					}

					await Promise.race([hp, tf()])
				})
			}

			void test("signs auth token without signature when algorithm is disabled", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_ALGORITHM: "",
						DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "",
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtAlg(s, "none", "")
				}

				await Promise.race([hp, tf()])
			})
		})

		void test.suite("auth token expiration time", () => {
			void test("sets default auth token expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void test("sets custom auth token expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 1800000,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 1800000)
				}

				await Promise.race([hp, tf()])
			})

			void test("creates auth token without expiration when ttl is disabled", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 0)
				}

				await Promise.race([hp, tf()])
			})

			let va: number[] = [3600000, 0]

			for (let expiresIn of va) {
				for (let ttl of va) {
					let m = 0

					let a: number[] = []

					if (expiresIn) {
						a.push(expiresIn)
					}

					if (ttl) {
						a.push(ttl)
					}

					if (a.length !== 0) {
						m = Math.min(...a)
					}

					void test(`expiresIn=${expiresIn} ttl=${ttl}`, async(t) => {
						let [hs, ha] = await setupHttp(t)

						let hp = onRequest(t, hs, async(_, res) => {
							let so: jwt.SignOptions = {
								algorithm: "none",
							}

							if (expiresIn) {
								so.expiresIn = expiresIn / 1000
							}

							let t = r.safeSync(jwt.sign, {}, "", so)
							assert.ok(t.err === undefined)

							let b: Record<string, unknown> = {
								access_token: t.v,
								token_type: "test",
							}

							let s = await sendJson(res, 200, b)
							assert.ok(s.err === undefined)
						})

						let tf = async(): Promise<void> => {
							let e: object = {
								DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
								DOCSPACE_OAUTH_AUTH_TOKEN_TTL: ttl,
							}

							let a = await setup(t, e)

							let s = await requestAccessToken(a)

							checkJwtTtl(s, m)
						}

						await Promise.race([hp, tf()])
					})
				}
			}

			void test("sets auth token expiration to current time when upstream is expired", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						exp: Math.floor((now - 3600000) / 1000),
					}

					let so: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", so)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now, 3000))
					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})
		})

		void test.suite("auth token not-before time", () => {
			void test("sets auth token not-before to current time by default", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void test("respects future not-before from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now + 3600000, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void test("resets auth token not-before when it exceeds expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 7200000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 3600000,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
					assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now + 3600000, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void test("does not modify auth token not-before when upstream not-before is in the past", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now - 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})
		})

		void test.suite("auth token payload", () => {
			void test("embeds upstream token in auth token payload", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hj: jwt.Jwt | null | undefined

				let hp = onRequest(t, hs, async(_, res) => {
					let so: jwt.SignOptions = {
						algorithm: "HS256",
						expiresIn: 3600000 / 1000,
					}

					let t = r.safeSync(jwt.sign, {}, "qqq", so)
					assert.ok(t.err === undefined)

					let co: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					hj = decode(t.v, co)
					assert.ok(hj)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					assert.ok(hj)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					assert.deepEqual(j.payload.hdr, hj.header)
					assert.deepEqual(j.payload.pld, hj.payload)
					assert.deepEqual(j.payload.sgn, hj.signature)
				}

				await Promise.race([hp, tf()])
			})
		})

		void test.suite("token response", () => {
			void test("returns token_type from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, {}, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 200)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token_type: "test",
					}

					assert.partialDeepStrictEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})

			void test("returns refresh_token from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, {}, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
						refresh_token: "www",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "refresh_token")
					f.set("refresh_token", "zzz")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 200)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						refresh_token: "www",
					}

					assert.partialDeepStrictEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})

			let va = [3600000, 1800000, 0]

			for (let expiresIn of va) {
				for (let expires_in of va) {
					for (let ttl of va) {
						let m = 0

						let a: number[] = []

						if (expiresIn) {
							a.push(expiresIn)
						}

						if (expires_in) {
							a.push(expires_in)
						}

						if (ttl) {
							a.push(ttl)
						}

						if (a.length !== 0) {
							m = Math.min(...a)
						}

						void test(`expiresIn=${expiresIn} expires_in=${expires_in} ttl=${ttl}`, async(t) => {
							let [hs, ha] = await setupHttp(t)

							let hp = onRequest(t, hs, async(_, res) => {
								let so: jwt.SignOptions = {
									algorithm: "none",
								}

								if (expiresIn) {
									so.expiresIn = expiresIn / 1000
								}

								let t = r.safeSync(jwt.sign, {}, "", so)
								assert.ok(t.err === undefined)

								let b: Record<string, unknown> = {
									access_token: t.v,
									token_type: "test",
								}

								if (expires_in) {
									b.expires_in = expires_in / 1000
								}

								let s = await sendJson(res, 200, b)
								assert.ok(s.err === undefined)
							})

							let tf = async(): Promise<void> => {
								let e: object = {
									DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
									DOCSPACE_OAUTH_AUTH_TOKEN_TTL: ttl,
								}

								let a = await setup(t, e)

								let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
								assert.ok(u.err === undefined)

								let f = new URLSearchParams()

								f.set("grant_type", "authorization_code")
								f.set("code", "vvv")

								let i: RequestInit = {
									method: "POST",
									headers: {
										"Content-Type": "application/x-www-form-urlencoded",
									},
									body: f.toString(),
								}

								let fetch = withAuth(globalThis.fetch)

								let res = await r.safeAsync(fetch, u.v, i)
								assert.ok(res.err === undefined)

								assert.ok(res.v.status === 200)

								let b = await readFetchJson(res.v)
								assert.ok(b.err === undefined)

								assert.ok(b.v)
								assert.ok(typeof b.v === "object")

								if (m) {
									assert.ok("expires_in" in b.v && typeof b.v.expires_in === "number")
									assert.ok(inDelta(b.v.expires_in, m / 1000, 3000))
								} else {
									assert.ok(!("expires_in" in b.v))
								}
							}

							await Promise.race([hp, tf()])
						})
					}
				}
			}
		})
	})
})
