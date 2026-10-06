/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as officeApi from "../lib/office-api.ts"

const base = "https://api.onlyoffice.com/docs/office-api/usage-api/"

const index = `# ONLYOFFICE Docs: Office API — Document API

> Although a document consists of various elements.

## Overview

- [Document API](${base}document-api.md): Although a document consists of various elements.

## Api

- [Api](${base}document-api/Api.md): The main class of the Document API.
- [Api.CreateParagraph](${base}document-api/Api/Methods/CreateParagraph.md): Creates a new paragraph.

## ApiParagraph

- [ApiParagraph](${base}document-api/ApiParagraph.md): Class representing a paragraph.
- [ApiParagraph.AddText](${base}document-api/ApiParagraph/Methods/AddText.md): Adds some text to the current paragraph.
- [ApiParagraph.SetJc](${base}document-api/ApiParagraph/Methods/SetJc.md): Sets the paragraph contents justification.

## Enumeration

- [Drawing](${base}document-api/Enumeration/Drawing.md): Any valid drawing element.
`

void test.suite("office api reference", () => {
  void test("parses entries of an index", () => {
    let a = officeApi.parseIndex(index)

    let x: officeApi.ReferenceEntry[] = [
      {kind: "overview", name: "Document API", description: "Although a document consists of various elements.", url: `${base}document-api.md`},
      {kind: "class", name: "Api", description: "The main class of the Document API.", url: `${base}document-api/Api.md`},
      {kind: "method", name: "Api.CreateParagraph", description: "Creates a new paragraph.", url: `${base}document-api/Api/Methods/CreateParagraph.md`},
      {kind: "class", name: "ApiParagraph", description: "Class representing a paragraph.", url: `${base}document-api/ApiParagraph.md`},
      {kind: "method", name: "ApiParagraph.AddText", description: "Adds some text to the current paragraph.", url: `${base}document-api/ApiParagraph/Methods/AddText.md`},
      {kind: "method", name: "ApiParagraph.SetJc", description: "Sets the paragraph contents justification.", url: `${base}document-api/ApiParagraph/Methods/SetJc.md`},
      {kind: "enumeration", name: "Drawing", description: "Any valid drawing element.", url: `${base}document-api/Enumeration/Drawing.md`},
    ]

    assert.deepEqual(a, x)
  })

  void test("finds an entry by its exact name before one that differs in case", () => {
    let a = officeApi.parseIndex(index)

    assert.equal(officeApi.findEntry(a, "ApiParagraph", ["class"])?.name, "ApiParagraph")
    assert.equal(officeApi.findEntry(a, "apiparagraph.addtext", ["method"])?.name, "ApiParagraph.AddText")
    assert.equal(officeApi.findEntry(a, "Drawing", ["class"]), undefined)
    assert.equal(officeApi.findEntry(a, "Drawing", ["class", "enumeration"])?.kind, "enumeration")
  })

  void test("searches names before descriptions and skips the overview", () => {
    let a = officeApi.parseIndex(index)

    let n = officeApi.searchEntries(a, "Paragraph").map((e) => e.name)

    assert.deepEqual(n, ["Api.CreateParagraph", "ApiParagraph", "ApiParagraph.AddText", "ApiParagraph.SetJc"])

    n = officeApi.searchEntries(a, "add text").map((e) => e.name)

    assert.deepEqual(n, ["ApiParagraph.AddText"])

    assert.deepEqual(officeApi.searchEntries(a, "document elements"), [])
    assert.deepEqual(officeApi.searchEntries(a, "  "), [])
  })

  void test("reads pages listed in the index and caches them", async() => {
    let c: string[] = []

    let fetch = (input: unknown): Promise<Response> => {
      let u = input instanceof Request ? input.url : String(input)
      c.push(u)

      if (u === `${base}document-api/llms.txt`) {
        return Promise.resolve(new Response(index))
      }

      if (u === `${base}document-api/ApiParagraph/Methods/AddText.md`) {
        return Promise.resolve(new Response(`---\nsidebar_position: 1\n---\n\n# AddText\n\nReturns [ApiRun](${base}document-api/ApiRun.md).\n`))
      }

      return Promise.resolve(new Response("", {status: 404}))
    }

    let rf = new officeApi.Reference({baseUrl: base, userAgent: "", ttl: 60000, fetch})

    let ir = await rf.index("document")
    assert.ok(!ir.err)

    ir = await rf.index("document")
    assert.ok(!ir.err)

    let en = officeApi.findEntry(ir.v, "ApiParagraph.AddText", ["method"])
    assert.ok(en)

    let pr = await rf.page(en)
    assert.ok(!pr.err)
    assert.equal(pr.v, "# AddText\n\nReturns ApiRun.")

    pr = await rf.page(en)
    assert.ok(!pr.err)

    assert.deepEqual(c, [`${base}document-api/llms.txt`, `${base}document-api/ApiParagraph/Methods/AddText.md`])

    let e: officeApi.ReferenceEntry = {kind: "method", name: "X.Y", description: "", url: "https://example.com/x.md"}

    let er = await rf.page(e)
    assert.ok(er.err)

    let mr = await rf.index("spreadsheet")
    assert.ok(mr.err)
  })
})
