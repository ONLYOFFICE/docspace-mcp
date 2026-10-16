import fs from "node:fs/promises"
import path from "node:path"
import * as fflate from "fflate"
import type * as dist from "../lib/dist.ts"
import * as meta from "../lib/meta.ts"

const url = "https://mcp.onlyoffice.com/mcp"

const files: Record<string, string> = {
  "assets/icon.png": "docs/icon.png",
}

async function main(): Promise<void> {
  let pc = await fs.readFile("plugin.template.json", "utf8")

  let po = JSON.parse(pc) as dist.Plugin

  po.version = meta.version

  let mo: dist.PluginMcp = {
    $schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
    mcpServers: {
      [po.name]: {
        type: "streamable-http",
        url,
        extensions: {
          "com.openai": {
            auth: {
              type: "oauth",
              client: {
                mode: "dcr",
              },
            },
          },
        },
      },
    },
  }

  await fs.rm("./plugin/", {recursive: true, force: true})

  let z: fflate.Zippable = {}

  for (let [t, f] of Object.entries(files)) {
    let p = path.join("./plugin/", t)
    await fs.mkdir(path.dirname(p), {recursive: true})
    await fs.copyFile(f, p)
    z[t] = await fs.readFile(f)
  }

  pc = JSON.stringify(po, null, 2)
  await fs.writeFile("./plugin/plugin.json", pc)
  z["plugin.json"] = fflate.strToU8(pc)

  let mc = JSON.stringify(mo, null, 2)
  await fs.writeFile("./plugin/mcp.json", mc)
  z["mcp.json"] = fflate.strToU8(mc)

  await fs.writeFile(
    `./onlyoffice-docspace-plugin-${meta.version}.zip`,
    fflate.zipSync(z),
  )
}

await main()
