/**
 * @module test
 */

import assert from "node:assert/strict"
import fs from "node:fs/promises"
import test from "node:test"
import ajv from "ajv"
import ajvFormats from "ajv-formats"
import * as spec from "../lib/config/spec.ts"
import * as config from "../lib/config.ts"
import * as dist from "../lib/dist.ts"
import * as r from "../lib/util/result.ts"
import type {SetupMcpOptions} from "./util.ts"
import {once, setupMcp} from "./util.ts"

async function readDetail(): Promise<r.Result<dist.Detail, Error>> {
  const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

  const f = await r.safeAsync(rf, "./server.json", "utf8")
  if (f.err) {
    return r.error(new Error("Reading file", {cause: f.err}))
  }

  const j = r.safeSync(JSON.parse, f.v)
  if (j.err) {
    return r.error(new Error("Parsing json", {cause: j.err}))
  }

  const s = dist.DetailSchema.safeParse(j.v)
  if (s.error) {
    return r.error(new Error("Parsing schema", {cause: s.error}))
  }

  return r.ok(s.data)
}

void test.suite("server detail", () => {
  const readDetailOnce = once(readDetail)

  void test.suite("general", () => {
    void test("validates against $schema", async() => {
      const m = await readDetailOnce()
      assert.ok(m.err === undefined)

      const a = new ajv.Ajv()
      a.addKeyword("example")
      ajvFormats.default(a)

      const s = await r.safeAsync(fetch, m.v.$schema)
      assert.ok(s.err === undefined)

      const o = await r.safeAsync(s.v.json.bind(s.v))
      assert.ok(o.err === undefined)

      const v = r.safeSync(a.compile.bind(a), o.v)
      assert.ok(v.err === undefined)

      assert.ok(v.v(m.v))
    })
  })

  void test.suite("packages", () => {
    void test("matches server metadata", async(t) => {
      const m = await readDetailOnce()
      assert.ok(m.err === undefined)

      const o: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {},
      }

      const c = await setupMcp(t, o)

      const i = c.getServerVersion()
      assert.ok(i !== undefined)

      assert.ok(m.v.version === i.version)

      for (const p of m.v.packages) {
        switch (p.registryType) {
        case "mcpb":
          assert.ok(p.version === i.version)
          break

        case "npm":
          assert.ok(p.version === i.version)
          break

        case "oci":
          assert.ok(p.identifier.endsWith(`:${i.version}`))
          break
        }
      }
    })

    void test("declares all env variables", async() => {
      const m = await readDetailOnce()
      assert.ok(m.err === undefined)

      for (const p of m.v.packages) {
        let d: spec.ItemDistribution | undefined

        switch (p.registryType) {
        case "mcpb":
          d = "mcpb"
          break

        case "npm":
          d = "js"
          break

        case "oci":
          d = "oci"
          break
        }

        let n = 0

        for (const i of Object.values(spec)) {
          if (
            i.distributions.includes(d) &&
            i.transports.includes(p.transport.type)
          ) {
            const k = `${config.envPrefix}${i.env}`

            let a: dist.DetailValue | undefined

            for (const v of p.environmentVariables) {
              if (v.name === k) {
                a = v
                break
              }
            }

            assert.ok(a !== undefined)

            const e: dist.DetailValue = {
              description: i.description,
              isRequired: false,
              format: i.type,
              isSecret: i.sensitive,
              default: String(i.default),
              choices: i.choices,
              name: k,
            }

            assert.deepEqual(a, e)

            n += 1
          }
        }

        assert.ok(p.environmentVariables.length === n)
      }
    })

    void test("declares all headers", async() => {
      const m = await readDetailOnce()
      assert.ok(m.err === undefined)

      for (const p of m.v.packages) {
        if (p.transport.type === "stdio") {
          continue
        }

        assert.ok(p.transport.headers !== undefined)

        let d: spec.ItemDistribution | undefined

        switch (p.registryType) {
        case "mcpb":
          d = "mcpb"
          break

        case "npm":
          d = "js"
          break

        case "oci":
          d = "oci"
          break
        }

        let n = 0

        for (const i of Object.values(spec)) {
          if (
            i.distributions.includes(d) &&
            i.transports.includes(p.transport.type) &&
            i.header
          ) {
            const k = `${spec.requestHeaderPrefix.default}${i.header}`

            let a: dist.DetailValue | undefined

            for (const v of p.transport.headers) {
              if (v.name === k) {
                a = v
                break
              }
            }

            assert.ok(a !== undefined)

            const e: dist.DetailValue = {
              description: i.description,
              isRequired: false,
              format: i.type,
              isSecret: i.sensitive,
              default: String(i.default),
              choices: i.choices,
              name: k,
            }

            assert.deepEqual(a, e)

            n += 1
          }
        }

        assert.ok(p.transport.headers.length === n)
      }
    })
  })

  void test.suite("remotes", () => {
    void test("declares all headers", async() => {
      const m = await readDetailOnce()
      assert.ok(m.err === undefined)

      for (const p of m.v.remotes) {
        if (p.type === "stdio") {
          continue
        }

        assert.ok(p.headers !== undefined)

        let n = 0

        for (const i of Object.values(spec)) {
          if (i.header) {
            const k = `${spec.requestHeaderPrefix.default}${i.header}`

            let a: dist.DetailValue | undefined

            for (const v of p.headers) {
              if (v.name === k) {
                a = v
                break
              }
            }

            assert.ok(a !== undefined)

            const e: dist.DetailValue = {
              description: i.description,
              isRequired: false,
              format: i.type,
              isSecret: i.sensitive,
              default: String(i.default),
              choices: i.choices,
              name: k,
            }

            assert.deepEqual(a, e)

            n += 1
          }
        }

        assert.ok(p.headers.length === n)
      }
    })
  })
})
