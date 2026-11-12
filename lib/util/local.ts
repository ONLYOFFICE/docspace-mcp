/**
 * @module util/local
 */

import crypto from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import * as r from "./result.ts"

export const maxFileSize = 100 * 1024 * 1024 // 100 MiB

// Files that are not uploaded for this long were left by uploads that never
// happened or that failed.
export const staleAge = 24 * 60 * 60 * 1000 // 1 day

const fileIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export type LocalUpload = {
  fileId: string
  path: string
}

export type LocalFile = {
  path: string
  data: Uint8Array
}

export type LocalDirectoryConfig = {
  path: string
  client: string
}

export function directoryConfig(distribution: string, client: string): LocalDirectoryConfig {
  // Without the client path, the model has no way to put files into a
  // directory inside the container.
  if (distribution === "oci" && !client) {
    return {
      path: "",
      client: "",
    }
  }

  return {
    path: path.join(os.tmpdir(), "onlyoffice-apps-mcp", "uploads"),
    client,
  }
}

// One server may serve several conversations at once, so each upload gets a
// file name of its own instead of the name the file has on the portal. The
// directory stays the same, so the AI client asks for access to it only once.
export class LocalDirectory {
  private root: string
  private client: string

  constructor(config: LocalDirectoryConfig) {
    this.root = config.path
    this.client = config.client
  }

  async create(): Promise<r.Result<LocalUpload, Error>> {
    const rr = await this.prepare()
    if (rr.err) {
      return r.error(rr.err)
    }

    await this.removeStale(rr.v)

    const id = crypto.randomUUID()

    const u: LocalUpload = {
      fileId: id,
      path: this.toClient(rr.v, id),
    }

    return r.ok(u)
  }

  async read(fileId: string): Promise<r.Result<LocalFile, Error>> {
    if (!fileIdPattern.test(fileId)) {
      return r.error(new Error("The file ID is not one returned by prepare_local_upload."))
    }

    const rr = await this.prepare()
    if (rr.err) {
      return r.error(rr.err)
    }

    const rt = rr.v

    const tr = await r.safeAsync(() => fs.realpath(path.join(rt, fileId)))
    if (tr.err) {
      // The error of the file system names the path inside the container,
      // which means nothing to the model.
      return r.error(new Error(`The file is not saved to the path that prepare_local_upload returned for ${fileId}.`))
    }

    if (tr.v !== path.join(rt, fileId)) {
      return r.error(new Error("The file leads outside the local directory."))
    }

    // The file can be replaced with a link after the check above, so it is
    // opened without following links and then read only through the handle.
    // Windows has no O_NOFOLLOW, but creating links there needs elevated
    // privileges or the developer mode.
    const fl = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)

    const hr = await r.safeAsync(() => fs.open(tr.v, fl))
    if (hr.err) {
      if (isLinkError(hr.err)) {
        return r.error(new Error("The file leads outside the local directory."))
      }
      return r.error(new Error("Opening file.", {cause: hr.err}))
    }

    const h = hr.v

    try {
      const dr = await readHandle(h)
      if (dr.err) {
        return r.error(dr.err)
      }

      const f: LocalFile = {
        path: tr.v,
        data: dr.v,
      }

      return r.ok(f)
    } finally {
      await r.safeAsync(() => h.close())
    }
  }

  async remove(f: LocalFile): Promise<r.Result<void, Error>> {
    const rr = await r.safeAsync(() => fs.rm(f.path, {force: true}))
    if (rr.err) {
      return r.error(new Error("Removing file.", {cause: rr.err}))
    }

    return r.ok()
  }

  private async prepare(): Promise<r.Result<string, Error>> {
    if (!this.root) {
      return r.error(new Error("The local directory is not configured."))
    }

    const mr = await r.safeAsync(() => fs.mkdir(this.root, {recursive: true}))
    if (mr.err) {
      return r.error(new Error("Creating the local directory.", {cause: mr.err}))
    }

    const rr = await r.safeAsync(() => fs.realpath(this.root))
    if (rr.err) {
      return r.error(new Error("Resolving the local directory.", {cause: rr.err}))
    }

    return r.ok(rr.v)
  }

  private async removeStale(rt: string): Promise<void> {
    const dr = await r.safeAsync(() => fs.readdir(rt, {withFileTypes: true}))
    if (dr.err) {
      return
    }

    const t = Date.now() - staleAge

    for (const d of dr.v) {
      if (!d.isFile() || !fileIdPattern.test(d.name)) {
        continue
      }

      const p = path.join(rt, d.name)

      const sr = await r.safeAsync(() => fs.stat(p))
      if (sr.err || sr.v.mtimeMs > t) {
        continue
      }

      await r.safeAsync(() => fs.rm(p, {force: true}))
    }
  }

  private toClient(rt: string, id: string): string {
    if (!this.client) {
      return path.join(rt, id)
    }

    const s = isWindowsPath(this.client) ? "\\" : "/"

    return `${this.client.replace(/[\\/]+$/, "")}${s}${id}`
  }
}

async function readHandle(h: fs.FileHandle): Promise<r.Result<Uint8Array, Error>> {
  const sr = await r.safeAsync(() => h.stat())
  if (sr.err) {
    return r.error(new Error("Reading file information.", {cause: sr.err}))
  }

  const s = sr.v

  if (!s.isFile()) {
    return r.error(new Error("The path is not a file."))
  }

  // A hard link passes the path check, yet it may be the same file as one
  // outside the directory.
  if (s.nlink > 1) {
    return r.error(new Error("The file has hard links that may lead outside the local directory."))
  }

  if (s.size > maxFileSize) {
    return r.error(new Error(`The file is ${s.size} bytes, larger than the limit of ${maxFileSize} bytes.`))
  }

  // One byte more than the size shows that the file grew after the check.
  const b = new Uint8Array(s.size + 1)
  let n = 0

  while (n < b.byteLength) {
    const rr = await r.safeAsync(() => h.read(b, n, b.byteLength - n, n))
    if (rr.err) {
      return r.error(new Error("Reading file.", {cause: rr.err}))
    }

    if (rr.v.bytesRead === 0) {
      break
    }

    n += rr.v.bytesRead
  }

  if (n !== s.size) {
    return r.error(new Error("The file changed while it was read."))
  }

  return r.ok(b.subarray(0, n))
}

function isLinkError(err: Error): boolean {
  // Linux reports ELOOP for a link opened with O_NOFOLLOW, FreeBSD reports
  // EMLINK.
  const c = (err as NodeJS.ErrnoException).code
  return c === "ELOOP" || c === "EMLINK"
}

function isWindowsPath(p: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\")
}
