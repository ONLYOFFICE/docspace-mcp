/**
 * @module test
 */

import assert from "node:assert/strict"
import childProcess from "node:child_process"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import util from "node:util"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as utilLocal from "../lib/util/local.ts"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, readHttpData, sendJson, setupHttp, setupMcp} from "./util.ts"

// Bytes that are not valid UTF-8, so that a text round trip would corrupt
// them.
const binary = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28])

const execFile = util.promisify(childProcess.execFile)

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// Returns the temporary directory to give the server, the uploads directory
// the server uses inside it and a directory outside the uploads one.
async function setupDirs(t: test.TestContext): Promise<[string, string, string]> {
  const b = await fs.mkdtemp(path.join(os.tmpdir(), "docspace-mcp-local-"))

  const onAfter: test.TestContextHookFn = async() => {
    await fs.rm(b, {recursive: true, force: true})
  }

  t.after(onAfter)

  const d = path.join(b, "onlyoffice-apps-mcp", "uploads")
  const o = path.join(b, "outside")

  await fs.mkdir(d, {recursive: true})
  await fs.mkdir(o, {recursive: true})

  await fs.writeFile(path.join(o, "secret.txt"), "secret")

  return [b, d, o]
}

async function createUpload(ld: utilLocal.LocalDirectory): Promise<utilLocal.LocalUpload> {
  const cr = await ld.create()
  assert.ok(cr.err === undefined)
  return cr.v
}

void test.suite("local directory", () => {
  void test("returns a new file in the same directory for every upload", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const a = await createUpload(ld)
    const b = await createUpload(ld)

    assert.notEqual(a.fileId, b.fileId)

    const rd = await fs.realpath(d)

    for (const u of [a, b]) {
      assert.match(u.fileId, uuidPattern)
      assert.ok(u.path === path.join(rd, u.fileId))
    }

    // Nothing is created besides the directory.
    assert.deepEqual(await fs.readdir(d), [])
  })

  void test("keeps files of different uploads apart", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const a = await createUpload(ld)
    const b = await createUpload(ld)

    await fs.writeFile(a.path, "a")
    await fs.writeFile(b.path, "b")

    const fa = await ld.read(a.fileId)
    assert.ok(fa.err === undefined)
    assert.deepEqual(Buffer.from(fa.v.data).toString(), "a")

    const fb = await ld.read(b.fileId)
    assert.ok(fb.err === undefined)
    assert.deepEqual(Buffer.from(fb.v.data).toString(), "b")
  })

  void test("reads a binary file", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    await fs.writeFile(u.path, binary)

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err === undefined)
    assert.deepEqual(fr.v.data, binary)
  })

  void test("refuses IDs that are not file IDs", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    await fs.writeFile(u.path, binary)

    const ids = [
      "",
      ".",
      "..",
      "../outside/secret.txt",
      `${u.fileId}.docx`,
      `../uploads/${u.fileId}`,
      u.fileId.toUpperCase(),
      u.path,
    ]

    for (const id of ids) {
      const fr = await ld.read(id)
      assert.ok(fr.err !== undefined, id)
      assert.match(fr.err.message, /not one returned by prepare_local_upload/)
    }
  })

  void test("refuses a missing file without naming the path", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err !== undefined)
    assert.ok(fr.err.cause === undefined)
    assert.ok(!fr.err.message.includes(d))
  })

  void test("refuses links that lead outside the directory", async(t) => {
    const [, d, o] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    // Creating a file link on Windows needs elevated privileges or the
    // developer mode.
    const l = await r.safeAsync(() => fs.symlink(path.join(o, "secret.txt"), u.path))
    if (l.err) {
      t.skip("symbolic links are not available")
      return
    }

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err !== undefined)
    assert.match(fr.err.message, /outside the local directory/)
  })

  void test("refuses hard links to files outside the directory", async(t) => {
    const [, d, o] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    const l = await r.safeAsync(() => fs.link(path.join(o, "secret.txt"), u.path))
    if (l.err) {
      t.skip("hard links are not available")
      return
    }

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err !== undefined)
    assert.match(fr.err.message, /hard links/)
  })

  void test("refuses a FIFO without waiting for a writer", {timeout: 5000}, async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    // Git for Windows ships an mkfifo that emulates FIFOs with ordinary files.
    const m = process.platform === "win32" ?
      r.error(new Error("FIFOs are not available.")) :
      await r.safeAsync(() => execFile("mkfifo", [u.path]))
    if (m.err) {
      t.skip("FIFOs are not available")
      return
    }

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err !== undefined)
    assert.match(fr.err.message, /not a file/)
  })

  void test("refuses a directory as a file", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    await fs.mkdir(u.path)

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err !== undefined)
  })

  void test("removes the file", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const u = await createUpload(ld)

    await fs.writeFile(u.path, binary)

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err === undefined)

    const rr = await ld.remove(fr.v)
    assert.ok(rr.err === undefined)

    const sr = await r.safeAsync(() => fs.stat(u.path))
    assert.ok(sr.err !== undefined)
  })

  void test("removes stale upload files only", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: ""})

    const s = await createUpload(ld)
    const f = await createUpload(ld)

    await fs.writeFile(s.path, "stale")
    await fs.writeFile(f.path, "fresh")
    await fs.writeFile(path.join(d, "other.txt"), "other")

    const o = new Date(Date.now() - utilLocal.staleAge - 60 * 1000)

    await fs.utimes(s.path, o, o)
    await fs.utimes(path.join(d, "other.txt"), o, o)

    await createUpload(ld)

    assert.deepEqual((await fs.readdir(d)).sort(), [f.fileId, "other.txt"].sort())
  })

  void test("creates a missing directory", async(t) => {
    const [, d] = await setupDirs(t)

    const p = path.join(d, "missing", "uploads")

    const ld = new utilLocal.LocalDirectory({path: p, client: ""})

    await createUpload(ld)

    const sr = await fs.stat(p)
    assert.ok(sr.isDirectory())
  })

  void test("refuses everything when not configured", async() => {
    const ld = new utilLocal.LocalDirectory({path: "", client: ""})

    const cr = await ld.create()
    assert.ok(cr.err !== undefined)

    const fr = await ld.read("674ea7f9-fe93-4980-8003-5aeda2996e79")
    assert.ok(fr.err !== undefined)
  })

  void test("returns paths of a Windows client", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: "C:\\Users\\me\\DocSpace\\"})

    const u = await createUpload(ld)

    assert.ok(u.path === `C:\\Users\\me\\DocSpace\\${u.fileId}`)

    await fs.writeFile(path.join(d, u.fileId), binary)

    const fr = await ld.read(u.fileId)
    assert.ok(fr.err === undefined)
    assert.deepEqual(fr.v.data, binary)
  })

  void test("returns paths of a POSIX client", async(t) => {
    const [, d] = await setupDirs(t)

    const ld = new utilLocal.LocalDirectory({path: d, client: "/home/me/DocSpace"})

    const u = await createUpload(ld)

    assert.ok(u.path === `/home/me/DocSpace/${u.fileId}`)
  })
})

void test.suite("local directory config", () => {
  void test("uses the uploads directory in the temporary directory", () => {
    const e = path.join(os.tmpdir(), "onlyoffice-apps-mcp", "uploads")

    assert.deepEqual(utilLocal.directoryConfig("js", ""), {path: e, client: ""})
    assert.deepEqual(utilLocal.directoryConfig("mcpb", ""), {path: e, client: ""})
    assert.deepEqual(utilLocal.directoryConfig("oci", "/home/me/DocSpace"), {path: e, client: "/home/me/DocSpace"})
  })

  void test("turns the tools off in the container without the client path", () => {
    assert.deepEqual(utilLocal.directoryConfig("oci", ""), {path: "", client: ""})
  })
})

function stdioEnv(base: string, tmp: string, client?: string): Record<string, string> {
  const e: Record<string, string> = {
    DOCSPACE_BASE_URL: base,
    DOCSPACE_API_KEY: "xxx",
    // os.tmpdir reads TMPDIR on POSIX and TEMP or TMP on Windows.
    TMPDIR: tmp,
    TEMP: tmp,
    TMP: tmp,
  }

  if (client !== undefined) {
    e.DOCSPACE_LOCAL_DIRECTORY_CLIENT = client
  }

  return e
}

async function prepareUpload(t: test.TestContext, env: Record<string, string>): Promise<types.CallToolResult> {
  const so: SetupMcpOptions = {
    transport: "stdio",
    host: "",
    port: 0,
    env,
  }

  const cl = await setupMcp(t, so)

  // The client validates structured content against the output schema it
  // caches on listing tools.
  const lr = await r.safeAsync(cl.listTools.bind(cl))
  assert.ok(lr.err === undefined)

  const n = lr.v.tools.map((t) => t.name)

  assert.ok(n.includes("prepare_local_upload"))
  assert.ok(n.includes("upload_local_file"))

  const cp: types.CallToolRequest["params"] = {
    name: "prepare_local_upload",
    arguments: {},
  }

  const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
  assert.ok(cr.err === undefined)

  return cr.v as types.CallToolResult
}

void test.suite("local tools", () => {
  void test("prepare an upload in the temporary directory", async(t) => {
    const [b, d] = await setupDirs(t)

    const cr = await prepareUpload(t, stdioEnv("http://localhost/", b))
    assert.ok(!cr.isError, JSON.stringify(cr.content))

    const sc = cr.structuredContent as utilLocal.LocalUpload
    assert.match(sc.fileId, uuidPattern)
    assert.ok(sc.path === path.join(await fs.realpath(d), sc.fileId))
  })

  void test("prepare an upload under the client path", async(t) => {
    const [b] = await setupDirs(t)

    const cr = await prepareUpload(t, stdioEnv("http://localhost/", b, "C:\\Users\\me\\DocSpace"))
    assert.ok(!cr.isError, JSON.stringify(cr.content))

    const sc = cr.structuredContent as utilLocal.LocalUpload
    assert.ok(sc.path === `C:\\Users\\me\\DocSpace\\${sc.fileId}`)
  })

  void test("refuse a relative client path", async(t) => {
    const [b] = await setupDirs(t)

    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: stdioEnv("http://localhost/", b, "relative/dir"),
    }

    const cl = await setupMcp(t, so)

    const cp: types.CallToolRequest["params"] = {
      name: "prepare_local_upload",
      arguments: {},
    }

    const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
    assert.ok(cr.err === undefined)
    assert.ok(cr.v.isError)
    assert.match(JSON.stringify(cr.v.content), /Local directory client path is not an absolute path/)
  })

  void test("upload a binary file under the given name and remove it", async(t) => {
    const [b] = await setupDirs(t)

    const [hs, ha] = await setupHttp(t)

    let chunk: Buffer | undefined
    let session: unknown

    const l: AsyncRequestListener = async(req, res) => {
      if (req.method === "POST" && req.url === "/api/2.0/files/5/upload/create_session") {
        const dr = await readHttpData(req)
        assert.ok(dr.err === undefined)

        session = JSON.parse(Buffer.concat(dr.v).toString("utf8"))

        const s = await sendJson(res, 200, {
          response: {
            id: "session",
          },
          count: 1,
          links: [],
          status: 0,
          statusCode: 200,
        })
        assert.ok(s.err === undefined)
        return
      }

      if (req.method === "POST" && req.url === "/ChunkedUploader.ashx?uid=session") {
        const dr = await readHttpData(req)
        assert.ok(dr.err === undefined)

        chunk = Buffer.concat(dr.v)

        const s = await sendJson(res, 201, {
          success: true,
          data: {
            id: 10,
            title: "report.docx",
          },
          message: "",
        })
        assert.ok(s.err === undefined)
        return
      }

      throw new Error(`Unexpected request ${req.method} ${req.url}`)
    }

    const hp = onRequest(t, hs, l)

    let p = ""

    const tf = async(): Promise<void> => {
      const so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: stdioEnv(`http://[${ha.address}]:${ha.port}/`, b),
      }

      const cl = await setupMcp(t, so)

      const lr = await r.safeAsync(cl.listTools.bind(cl))
      assert.ok(lr.err === undefined)

      const pp: types.CallToolRequest["params"] = {
        name: "prepare_local_upload",
        arguments: {},
      }

      const pr = await r.safeAsync(cl.callTool.bind(cl), pp)
      assert.ok(pr.err === undefined)
      assert.ok(!pr.v.isError, JSON.stringify(pr.v.content))

      const u = pr.v.structuredContent as utilLocal.LocalUpload

      p = u.path

      await fs.writeFile(p, binary)

      const cp: types.CallToolRequest["params"] = {
        name: "upload_local_file",
        arguments: {
          parentId: 5,
          fileId: u.fileId,
          filename: "report.docx",
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)
      assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))
    }

    await Promise.race([hp, tf()])

    assert.ok(typeof session === "object" && session !== null)
    assert.ok((session as Record<string, unknown>).fileName === "report.docx")
    assert.ok((session as Record<string, unknown>).fileSize === binary.length)

    assert.ok(chunk !== undefined)
    assert.ok(chunk.includes(Buffer.from(binary)))

    const sr = await r.safeAsync(() => fs.stat(p))
    assert.ok(sr.err !== undefined)
  })

  void test("refuse an ID not returned by prepare_local_upload", async(t) => {
    const [b] = await setupDirs(t)

    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: stdioEnv("http://localhost/", b),
    }

    const cl = await setupMcp(t, so)

    const cp: types.CallToolRequest["params"] = {
      name: "upload_local_file",
      arguments: {
        parentId: 5,
        fileId: "../../outside/secret.txt",
        filename: "secret.txt",
      },
    }

    const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
    assert.ok(cr.err === undefined)
    assert.ok(cr.v.isError)
    assert.match(JSON.stringify(cr.v.content), /not one returned by prepare_local_upload/)
  })
})
