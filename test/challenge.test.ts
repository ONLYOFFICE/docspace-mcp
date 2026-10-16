/**
 * @module test
 */

import assert from "node:assert/strict"
import type net from "node:net"
import test from "node:test"
import * as r from "../lib/util/result.ts"
import type {SetupBinOptions} from "./util.ts"
import {randomAddress, readFetchText, setupBin} from "./util.ts"

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
      ...e,
    },
  }

  await setupBin(t, o)

  return a.v
}

async function requestChallenge(a: net.AddressInfo): Promise<Response> {
  let u = r.safeNew(URL, "/.well-known/openai-apps-challenge", `http://[${a.address}]:${a.port}/`)
  assert.ok(u.err === undefined)

  let res = await r.safeAsync(fetch, u.v)
  assert.ok(res.err === undefined)

  return res.v
}

void test.suite("openai apps challenge", () => {
  void test("serves the configured token", async(t) => {
    let a = await setup(t, {
      DOCSPACE_SERVER_OPENAI_APPS_CHALLENGE: " xxx ",
    })

    let res = await requestChallenge(a)
    assert.ok(res.status === 200)

    let b = await readFetchText(res)
    assert.ok(b.err === undefined, b.err)
    assert.ok(b.v === "xxx")
  })

  void test("responds with not found when the token is not set", async(t) => {
    let a = await setup(t, {})

    let res = await requestChallenge(a)
    assert.ok(res.status === 404)
  })
})
