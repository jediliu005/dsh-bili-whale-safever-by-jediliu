export function parseJsonExact(text) {
  const source=String(text)
  return JSON.parse(source.replace(/"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g, token => {
    if (/^-?(?:0|[1-9]\d*)$/.test(token) && !Number.isSafeInteger(Number(token))) return JSON.stringify(token)
    return token
  }))
}
export async function exactJson(response) { return parseJsonExact(await response.text()) }
