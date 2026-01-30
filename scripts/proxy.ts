import {ProxyAgent, setGlobalDispatcher} from "undici"

if (process.env.HTTP_PROXY === undefined) {
	throw new Error("HTTP_PROXY environment variable is not set")
}

if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === undefined) {
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
}

setGlobalDispatcher(new ProxyAgent(process.env.HTTP_PROXY))

// https://github.com/gajus/global-agent/issues/52/#issuecomment-1134525621
// https://docs.proxyman.com/debug-devices/nodejs/#id-1.-node-fetch
