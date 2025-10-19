import React, { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

/**
 * Signature Playground v6 – PKCS#1-compatible (fixed)
 * - RSASSA-PKCS1-v1_5 + SHA-256 (WebCrypto)
 * - Canonical: HTTPMethod:EndpointUrl:lowercase(SHA256hex(minify(body))):TimeStamp
 * - Accepts private key: PKCS#8 (BEGIN PRIVATE KEY) or PKCS#1 (BEGIN RSA PRIVATE KEY)
 * - Accepts public key : SPKI (BEGIN PUBLIC KEY) or PKCS#1 (BEGIN RSA PUBLIC KEY)
 */

export default function SignaturePlaygroundV6() {
  const [tab, setTab] = useState("sign");
  const [dark, setDark] = useState(false);

  // SIGN state
  const [signJson, setSignJson] = useState(
    '{"partnerReferenceNo":"1234567890","amount":10000,"currency":"IDR"}'
  );
  const [httpMethodSign, setHttpMethodSign] = useState("POST");
  const [endpointSign, setEndpointSign] = useState("/v1/qris/create");
  const [timestampSign, setTimestampSign] = useState(nowIsoLocal());
  const [privatePem, setPrivatePem] = useState("");

  // VERIFY state
  const [verifyJson, setVerifyJson] = useState(
    '{"partnerReferenceNo":"1234567890","amount":10000,"currency":"IDR"}'
  );
  const [httpMethodVerify, setHttpMethodVerify] = useState("POST");
  const [endpointVerify, setEndpointVerify] = useState("/v1/qris/create");
  const [timestampVerify, setTimestampVerify] = useState(nowIsoLocal());
  const [publicPem, setPublicPem] = useState("");
  const [signatureB64, setSignatureB64] = useState("");

  // Options / output
  const [pemSingleLine, setPemSingleLine] = useState(true);
  const [wrap3, setWrap3] = useState(false);
  const [out, setOut] = useState("");

  // Previews
  const [signPrev, setSignPrev] = useState({
    minified: "",
    bodyHashHex: "",
    content: "",
    err: "",
  });
  const [verifyPrev, setVerifyPrev] = useState({
    minified: "",
    bodyHashHex: "",
    content: "",
    err: "",
  });
  useEffect(() => {
    recalcSignPreview(); /* eslint-disable-next-line */
  }, [signJson, httpMethodSign, endpointSign, timestampSign]);
  useEffect(() => {
    recalcVerifyPreview(); /* eslint-disable-next-line */
  }, [verifyJson, httpMethodVerify, endpointVerify, timestampVerify]);

  const signValidity = useMemo(
    () =>
      computeValidity(
        signJson,
        httpMethodSign,
        endpointSign,
        timestampSign,
        privatePem,
        true
      ),
    [signJson, httpMethodSign, endpointSign, timestampSign, privatePem]
  );
  const verifyValidity = useMemo(
    () =>
      computeValidity(
        verifyJson,
        httpMethodVerify,
        endpointVerify,
        timestampVerify,
        publicPem,
        false
      ),
    [verifyJson, httpMethodVerify, endpointVerify, timestampVerify, publicPem]
  );

  // ===== Utilities =====
  function minifyJsonStrict(src) {
    const obj = JSON.parse(src);
    return JSON.stringify(obj);
  }
  async function sha256HexLower(input) {
    const data =
      typeof input === "string" ? new TextEncoder().encode(input) : input;
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = new Uint8Array(digest);
    let hex = "";
    for (let i = 0; i < bytes.length; i++)
      hex += bytes[i].toString(16).padStart(2, "0");
    return hex;
  }
  async function buildCanonicalString(method, endpoint, bodyJson, timestamp) {
    const minified = minifyJsonStrict(bodyJson);
    const bodyHashHex = await sha256HexLower(minified);
    const content = `${String(
      method || ""
    ).toUpperCase()}:${endpoint}:${bodyHashHex}:${timestamp}`;
    return { minified, bodyHashHex, content };
  }
  function pemLabel(pemText) {
    const m = /-----BEGIN ([^-]+)-----/.exec(pemText || "");
    return m ? m[1].trim() : "";
  }
  function pemBodyToBytes(pemText) {
    const cleaned = (pemText || "")
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s+/g, "");
    const bin = atob(cleaned);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // DER helpers
  function derLen(len) {
    if (len < 128) return new Uint8Array([len]);
    const bytes = [];
    while (len > 0) {
      bytes.unshift(len & 0xff);
      len >>= 8;
    }
    return new Uint8Array([0x80 | bytes.length, ...bytes]);
  }
  function derNode(tag, body) {
    return new Uint8Array([tag, ...derLen(body.length), ...body]);
  }
  function derSequence(...parts) {
    const body = concatU8(...parts);
    return derNode(0x30, body);
  }
  function derOctetString(bytes) {
    return derNode(0x04, bytes);
  }
  function derBitString(bytes) {
    const body = new Uint8Array([0x00, ...bytes]);
    return derNode(0x03, body);
  } // 0 unused bits + data
  function concatU8(...arrs) {
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  // PKCS#1 -> PKCS#8 (private)
  function wrapPkcs1ToPkcs8(rsaDerBytes) {
    const version = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER 0
    const oidRsaEnc = new Uint8Array([
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ]); // 1.2.840.113549.1.1.1
    const nullParam = new Uint8Array([0x05, 0x00]);
    const algId = derSequence(oidRsaEnc, nullParam); // SEQ(OID, NULL)
    const pkOctet = derOctetString(rsaDerBytes); // OCTET STRING (RSAPrivateKey DER)
    const pkcs8 = derSequence(version, algId, pkOctet);
    return pkcs8;
  }
  // PKCS#1 (RSAPublicKey) -> SPKI (SubjectPublicKeyInfo)
  function wrapRsaPublicToSpki(rsaPubDerBytes) {
    const oidRsaEnc = new Uint8Array([
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ]);
    const nullParam = new Uint8Array([0x05, 0x00]);
    const algId = derSequence(oidRsaEnc, nullParam);
    const bitStr = derBitString(rsaPubDerBytes);
    const spki = derSequence(algId, bitStr);
    return spki;
  }

  async function importAnyPrivateKey(pem) {
    const label = pemLabel(pem);
    if (label.includes("PRIVATE KEY") && !label.includes("RSA")) {
      // PKCS#8
      const pkcs8 = pemBodyToBytes(pem);
      return crypto.subtle.importKey(
        "pkcs8",
        pkcs8,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );
    }
    if (label.includes("RSA PRIVATE KEY")) {
      // PKCS#1
      const rsa = pemBodyToBytes(pem);
      const pkcs8 = wrapPkcs1ToPkcs8(rsa);
      return crypto.subtle.importKey(
        "pkcs8",
        pkcs8.buffer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );
    }
    throw new Error(
      "Format private key tidak didukung. Gunakan BEGIN PRIVATE KEY (PKCS#8) atau BEGIN RSA PRIVATE KEY (PKCS#1)."
    );
  }
  async function importAnyPublicKey(pem) {
    const label = pemLabel(pem);
    if (label.includes("PUBLIC KEY") && !label.includes("RSA")) {
      // SPKI
      const spki = pemBodyToBytes(pem);
      return crypto.subtle.importKey(
        "spki",
        spki,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
    }
    if (label.includes("RSA PUBLIC KEY")) {
      // PKCS#1
      const rsaPub = pemBodyToBytes(pem);
      const spki = wrapRsaPublicToSpki(rsaPub);
      return crypto.subtle.importKey(
        "spki",
        spki.buffer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
    }
    throw new Error(
      "Format public key tidak didukung. Gunakan BEGIN PUBLIC KEY (SPKI) atau BEGIN RSA PUBLIC KEY (PKCS#1)."
    );
  }

  function abToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function toPem(label, arrayBuffer, singleLine = false) {
    const b64 = abToBase64(arrayBuffer);
    const payload = singleLine ? b64 : b64.match(/.{1,64}/g)?.join("\n") ?? b64;
    return `-----BEGIN ${label}-----\n${payload}\n-----END ${label}-----`;
  }
  function onLoadPem(e, setter) {
    const f = e.target.files?.[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => setter(String(r.result));
    r.readAsText(f);
  }
  function wrapIn3Lines(b64) {
    const clean = (b64 || "").replace(/\s+/g, "");
    const n = Math.ceil(clean.length / 3);
    return [clean.slice(0, n), clean.slice(n, 2 * n), clean.slice(2 * n)]
      .filter(Boolean)
      .join("\n");
  }
  function base64ToUint8(b64) {
    const norm = (b64 || "")
      .trim()
      .replace(/\s+/g, "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const bin = atob(norm);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function recalcSignPreview() {
    try {
      const { minified, bodyHashHex, content } = await buildCanonicalString(
        httpMethodSign,
        endpointSign,
        signJson,
        timestampSign
      );
      setSignPrev({ minified, bodyHashHex, content, err: "" });
    } catch (e) {
      setSignPrev({
        minified: "",
        bodyHashHex: "",
        content: "",
        err: e?.message || String(e),
      });
    }
  }
  async function recalcVerifyPreview() {
    try {
      const { minified, bodyHashHex, content } = await buildCanonicalString(
        httpMethodVerify,
        endpointVerify,
        verifyJson,
        timestampVerify
      );
      setVerifyPrev({ minified, bodyHashHex, content, err: "" });
    } catch (e) {
      setVerifyPrev({
        minified: "",
        bodyHashHex: "",
        content: "",
        err: e?.message || String(e),
      });
    }
  }

  async function doGenerate() {
    try {
      setOut("Memproses signature…");
      const { content } = await buildCanonicalString(
        httpMethodSign,
        endpointSign,
        signJson,
        timestampSign
      );
      const key = await importAnyPrivateKey(privatePem);
      const sig = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        new TextEncoder().encode(content)
      );
      const b64 = abToBase64(sig);
      setSignatureB64(b64);
      setOut(
        <>
          ✅ Signature generated:
          <br />
          <br />
          <CodeBlock dark={dark} title="Signature" text={b64} small />
        </>
      );

      toast("Signature berhasil dibuat");
    } catch (e) {
      setOut(`❌ Error generate: ${e?.message || e}`);
      toast("Gagal generate");
    }
  }
  async function doVerify() {
    try {
      setOut("Memverifikasi signature…");
      const { content } = await buildCanonicalString(
        httpMethodVerify,
        endpointVerify,
        verifyJson,
        timestampVerify
      );
      const key = await importAnyPublicKey(publicPem);
      const ok = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        base64ToUint8(signatureB64),
        new TextEncoder().encode(content)
      );
      setOut(ok ? "✅ Signature VALID" : "❌ Signature INVALID");
      toast(ok ? "Valid" : "Invalid");
    } catch (e) {
      setOut(`❌ Error verify: ${e?.message || e}`);
      toast("Gagal verify");
    }
  }

  async function genDemoKeypair() {
    try {
      const kp = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      );
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
      const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
      setPrivatePem(toPem("PRIVATE KEY", pkcs8, pemSingleLine));
      setPublicPem(toPem("PUBLIC KEY", spki, pemSingleLine));
      toast("Demo keypair dibuat");
    } catch (e) {
      toast("Gagal membuat keypair");
      setOut(`❌ Error keygen: ${e?.message || e}`);
    }
  }

  function toast(msg) {
    const el = document.createElement("div");
    el.textContent = msg;
    el.className =
      "fixed bottom-6 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl shadow-lg text-white bg-black/80 backdrop-blur-sm text-sm z-50";
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 1600);
  }
  const header = useMemo(
    () => (
      <motion.div
        layout
        className={`rounded-2xl p-5 mb-5 shadow ${
          dark
            ? "bg-gradient-to-r from-indigo-900 via-purple-900 to-slate-900"
            : "bg-gradient-to-r from-indigo-500 via-purple-500 to-sky-500"
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h1 className="font-bold text-2xl text-white">
              Signature Playground
            </h1>
            <p className="text-sm text-white/90">
              RSA PKCS#1 v1.5 + SHA-256 • Live canonical preview • PKCS#1/PKCS#8
              compatible
            </p>
          </div>
          <div className="flex flex-wrap gap-2 items-center">
            <label className="flex items-center gap-1 text-xs text-white">
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={pemSingleLine}
                onChange={(e) => setPemSingleLine(e.target.checked)}
              />
              PEM body single-line
            </label>
            <label className="flex items-center gap-1 text-xs text-white">
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={wrap3}
                onChange={(e) => setWrap3(e.target.checked)}
              />
              Signature 3 baris
            </label>
            <button
              onClick={genDemoKeypair}
              className="px-3 py-2 rounded-lg bg-white/95 hover:bg-white text-gray-900 shadow"
            >
              Generate Demo Keypair
            </button>
            <button
              onClick={() => setDark((v) => !v)}
              className="px-3 py-2 rounded-lg bg-white/20 hover:bg-white/30 text-white"
            >
              {dark ? "Light" : "Dark"}
            </button>
          </div>
        </div>
      </motion.div>
    ),
    [dark, pemSingleLine, wrap3]
  );

  const showFab = tab === "sign" ? signValidity.allOk : verifyValidity.allOk;

  return (
    <div
      className={`${
        dark ? "bg-gray-950 text-gray-100" : "bg-gray-50 text-gray-900"
      } min-h-screen p-4 md:p-8`}
    >
      <div className="max-w-7xl mx-auto">
        {header}
        <div
          className={`mb-4 inline-flex rounded-xl border ${
            dark ? "border-gray-700 bg-gray-900" : "border-gray-200 bg-white"
          } p-1 shadow-sm`}
        >
          <button
            onClick={() => setTab("sign")}
            className={`px-4 py-2 rounded-lg text-sm ${
              tab === "sign"
                ? "bg-indigo-600 text-white"
                : dark
                ? "text-gray-200"
                : "text-gray-700 hover:bg-gray-50"
            }`}
          >
            ✍️ Generate
          </button>
          <button
            onClick={() => setTab("verify")}
            className={`px-4 py-2 rounded-lg text-sm ${
              tab === "verify"
                ? "bg-emerald-600 text-white"
                : dark
                ? "text-gray-200"
                : "text-gray-700 hover:bg-gray-50"
            }`}
          >
            ✅ Verify
          </button>
        </div>

        <AnimatePresence mode="wait">
          {tab === "sign" ? (
            <motion.div
              key="sign"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="grid grid-cols-1 lg:grid-cols-2 gap-6"
            >
              <Section
                title="Payload & Canonical Fields"
                dark={dark}
                right={
                  <Badge
                    ok={signValidity.jsonOk && signValidity.metaOk}
                    msg={signValidity.allOk ? "Siap generate" : "Periksa input"}
                  />
                }
              >
                <TextAreaIn
                  dark={dark}
                  label="Payload JSON (akan di‑minify)"
                  value={signJson}
                  onChange={setSignJson}
                />
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                  <TextIn
                    dark={dark}
                    label="HTTP Method"
                    value={httpMethodSign}
                    onChange={(v) => setHttpMethodSign(v.toUpperCase())}
                  />
                  <TextIn
                    dark={dark}
                    label="Endpoint URL"
                    value={endpointSign}
                    onChange={setEndpointSign}
                  />
                  <div>
                    <TextIn
                      dark={dark}
                      label="Timestamp (ISO8601)"
                      value={timestampSign}
                      onChange={setTimestampSign}
                    />
                    <div className="mt-1 text-right">
                      <button
                        onClick={() => setTimestampSign(nowIsoLocal())}
                        className={`text-xs underline ${
                          dark ? "text-indigo-300" : "text-indigo-700"
                        }`}
                      >
                        Now (WIB)
                      </button>
                    </div>
                  </div>
                </div>
              </Section>

              <Section
                title="Private Key (PKCS#8 / RSA PKCS#1)"
                dark={dark}
                right={
                  <Badge
                    ok={!!privatePem}
                    msg={privatePem ? "Loaded" : "Belum ada key"}
                  />
                }
              >
                <div className="flex items-center justify-between mb-2">
                  <label
                    className={`text-xs px-2 py-1 rounded border cursor-pointer ${
                      dark
                        ? "bg-gray-800 border-gray-700"
                        : "bg-gray-50 border-gray-200"
                    }`}
                  >
                    Load .pem
                    <input
                      type="file"
                      accept=".pem"
                      className="hidden"
                      onChange={(e) => onLoadPem(e, setPrivatePem)}
                    />
                  </label>
                  <div className="text-xs opacity-70">
                    Menerima: BEGIN PRIVATE KEY / BEGIN RSA PRIVATE KEY
                  </div>
                </div>
                <TextAreaIn
                  dark={dark}
                  label=""
                  value={privatePem}
                  onChange={setPrivatePem}
                  rows={10}
                  placeholder={
                    "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\natau\n-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
                  }
                />
                <div className="mt-3 flex gap-2">
                  <button
                    disabled={!signValidity.allOk}
                    onClick={doGenerate}
                    className={`px-3 py-2 rounded-lg ${
                      !signValidity.allOk
                        ? "opacity-50 cursor-not-allowed"
                        : dark
                        ? "bg-indigo-600 hover:bg-indigo-500"
                        : "bg-indigo-600 hover:bg-indigo-700"
                    } text-white shadow`}
                  >
                    Generate
                  </button>
                </div>
                {signatureB64 && wrap3 && (
                  <div className="mt-3">
                    <CodeBlock
                      dark={dark}
                      title="Signature (Base64 – 3 lines)"
                      text={wrapIn3Lines(signatureB64)}
                      small
                    />
                  </div>
                )}
              </Section>

              <Section dark={dark} title="🔎 Live Preview (Generate)">
                {signPrev.err ? (
                  <div className="text-red-500 text-sm mb-2">
                    Error: {signPrev.err}
                  </div>
                ) : null}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <CodeBlock
                    dark={dark}
                    title="Body (minified)"
                    text={signPrev.minified}
                  />
                  <CodeBlock
                    dark={dark}
                    title="SHA256(body) hex (lower)"
                    text={signPrev.bodyHashHex}
                    small
                  />
                </div>
                <div className="mt-3">
                  <CodeBlock
                    dark={dark}
                    title="StringToSign"
                    text={signPrev.content}
                  />
                </div>
              </Section>

              <Section dark={dark} title="📜 Output / Status">
                <pre
                  className={`whitespace-pre-wrap break-words text-sm rounded-xl p-3 ${
                    dark
                      ? "bg-gray-900 border border-gray-700"
                      : "bg-gray-50 border border-gray-200"
                  }`}
                >
                  {out || "(belum ada output)"}
                </pre>
              </Section>
            </motion.div>
          ) : (
            <motion.div
              key="verify"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="grid grid-cols-1 lg:grid-cols-3 gap-6"
            >
              <Section
                title="Payload & Canonical Fields"
                dark={dark}
                right={
                  <Badge
                    ok={verifyValidity.jsonOk && verifyValidity.metaOk}
                    msg={
                      verifyValidity.allOk ? "Siap verifikasi" : "Periksa input"
                    }
                  />
                }
              >
                <TextAreaIn
                  dark={dark}
                  label="Payload JSON (akan di‑minify)"
                  value={verifyJson}
                  onChange={setVerifyJson}
                />
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                  <TextIn
                    dark={dark}
                    label="HTTP Method"
                    value={httpMethodVerify}
                    onChange={(v) => setHttpMethodVerify(v.toUpperCase())}
                  />
                  <TextIn
                    dark={dark}
                    label="Endpoint URL"
                    value={endpointVerify}
                    onChange={setEndpointVerify}
                  />
                  <div>
                    <TextIn
                      dark={dark}
                      label="Timestamp (ISO8601)"
                      value={timestampVerify}
                      onChange={setTimestampVerify}
                    />
                    <div className="mt-1 text-right">
                      <button
                        onClick={() => setTimestampVerify(nowIsoLocal())}
                        className={`text-xs underline ${
                          dark ? "text-emerald-300" : "text-emerald-700"
                        }`}
                      >
                        Now (WIB)
                      </button>
                    </div>
                  </div>
                </div>
              </Section>

              <Section
                title="Public Key (SPKI / RSA PKCS#1)"
                dark={dark}
                right={
                  <Badge
                    ok={!!publicPem}
                    msg={publicPem ? "Loaded" : "Belum ada key"}
                  />
                }
              >
                <div className="flex items-center justify-between mb-2">
                  <label
                    className={`text-xs px-2 py-1 rounded border cursor-pointer ${
                      dark
                        ? "bg-gray-800 border-gray-700"
                        : "bg-gray-50 border-gray-200"
                    }`}
                  >
                    Load .pem
                    <input
                      type="file"
                      accept=".pem"
                      className="hidden"
                      onChange={(e) => onLoadPem(e, setPublicPem)}
                    />
                  </label>
                  <div className="text-xs opacity-70">
                    Menerima: BEGIN PUBLIC KEY / BEGIN RSA PUBLIC KEY
                  </div>
                </div>
                <TextAreaIn
                  dark={dark}
                  label=""
                  value={publicPem}
                  onChange={setPublicPem}
                  rows={10}
                  placeholder={
                    "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\natau\n-----BEGIN RSA PUBLIC KEY-----\n...\n-----END RSA PUBLIC KEY-----"
                  }
                />
              </Section>

              <Section
                title="Signature (Base64)"
                dark={dark}
                right={
                  <Badge
                    ok={!!signatureB64}
                    msg={signatureB64 ? "Diisi" : "Kosong"}
                  />
                }
              >
                <TextAreaIn
                  dark={dark}
                  label=""
                  value={signatureB64}
                  onChange={setSignatureB64}
                  rows={10}
                  placeholder="Tempel signature Base64 di sini"
                />
                <div className="mt-3 flex gap-2">
                  <button
                    disabled={!verifyValidity.allOk}
                    onClick={doVerify}
                    className={`px-3 py-2 rounded-lg ${
                      !verifyValidity.allOk
                        ? "opacity-50 cursor-not-allowed"
                        : dark
                        ? "bg-emerald-600 hover:bg-emerald-500"
                        : "bg-emerald-600 hover:bg-emerald-700"
                    } text-white shadow`}
                  >
                    Verify
                  </button>
                </div>
              </Section>

              <Section dark={dark} title="🔎 Live Preview (Verify)">
                {verifyPrev.err ? (
                  <div className="text-red-500 text-sm mb-2">
                    Error: {verifyPrev.err}
                  </div>
                ) : null}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <CodeBlock
                    dark={dark}
                    title="Body (minified)"
                    text={verifyPrev.minified}
                  />
                  <CodeBlock
                    dark={dark}
                    title="SHA256(body) hex (lower)"
                    text={verifyPrev.bodyHashHex}
                    small
                  />
                </div>
                <div className="mt-3">
                  <CodeBlock
                    dark={dark}
                    title="StringToSign"
                    text={verifyPrev.content}
                  />
                </div>
              </Section>

              <Section dark={dark} title="📜 Output / Status">
                <pre
                  className={`whitespace-pre-wrap break-words text-sm rounded-xl p-3 ${
                    dark
                      ? "bg-gray-900 border border-gray-700"
                      : "bg-gray-50 border border-gray-200"
                  }`}
                >
                  {out || "(belum ada output)"}
                </pre>
              </Section>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {(tab === "sign" ? signValidity.allOk : verifyValidity.allOk) && (
            <motion.button
              onClick={tab === "sign" ? doGenerate : doVerify}
              initial={{ y: 80, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: 80, opacity: 0 }}
              transition={{ type: "spring", stiffness: 260, damping: 20 }}
              className={`fixed bottom-6 right-6 z-40 rounded-full px-5 py-3 shadow-xl ${
                tab === "sign" ? "bg-indigo-600" : "bg-emerald-600"
              } text-white`}
            >
              {tab === "sign" ? "Generate" : "Verify"}
            </motion.button>
          )}
        </AnimatePresence>

        <div className="mt-8 text-xs opacity-70">
          Kunci demo dibuat lokal di browser (tidak dikirim ke jaringan). Jangan
          unggah private key produksi.
        </div>
      </div>
    </div>
  );
}

function computeValidity(jsonStr, method, endpoint, ts, keyPem, isSign) {
  let jsonOk = true,
    metaOk = true;
  try {
    JSON.parse(jsonStr);
  } catch {
    jsonOk = false;
  }
  const methodOk = !!method && /^[A-Z]+$/.test(method);
  const endpointOk = !!endpoint && endpoint.startsWith("/");
  const tsOk =
    !!ts &&
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+\-]\d{2}:\d{2}|Z)$/.test(ts);
  const keyOk = keyPem
    ? keyPem.includes("PRIVATE KEY") || keyPem.includes("PUBLIC KEY")
    : false;
  const metaOk2 = methodOk && endpointOk && tsOk && keyOk;
  return { jsonOk, metaOk: metaOk2, allOk: jsonOk && metaOk2 };
}

function nowIsoLocal() {
  const d = new Date();

  // Komponen tanggal/waktu lokal (bukan UTC*)
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");

  // Offset timezone dalam menit; note: bernilai kebalikan (WIB = -420)
  const offsetMin = -d.getTimezoneOffset(); // jadi +420 untuk WIB
  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const offHH = String(Math.floor(abs / 60)).padStart(2, "0");
  const offMM = String(abs % 60).padStart(2, "0");

  return `${yyyy}-${mm}-${dd}T${hh}:${mi}:${ss}.${ms}${sign}${offHH}:${offMM}`;
}

function Badge({ ok, msg }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium ${
        ok ? "bg-emerald-100 text-emerald-900" : "bg-red-100 text-red-900"
      }`}
    >
      {ok ? "●" : "●"} {msg}
    </span>
  );
}
function Section({ title, children, right, dark }) {
  return (
    <div
      className={`rounded-2xl border shadow-sm ${
        dark
          ? "border-gray-700 bg-gradient-to-b from-gray-900 to-gray-950 dark-scroll"
          : "border-gray-200 bg-white"
      } p-4`}
    >
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-semibold">{title}</h2>
        <div>{right}</div>
      </div>
      {children}
    </div>
  );
}
function CodeBlock({ title, text, small, dark }) {
  return (
    <div
      className={`rounded-xl border ${
        dark
          ? "border-gray-700 bg-gray-900 text-gray-100"
          : "border-gray-200 bg-gray-50 text-gray-800"
      } p-3`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold opacity-80">{title}</span>
        <button
          className={`text-xs ${
            dark
              ? "bg-gray-800 hover:bg-gray-700"
              : "bg-white hover:bg-gray-100"
          } border rounded px-2 py-1`}
          onClick={() => navigator.clipboard.writeText(text || "")}
        >
          Copy
        </button>
      </div>
      <pre
        className={`whitespace-pre-wrap break-words ${
          small ? "text-xs" : "text-[13px]"
        }`}
      >
        {text || "(kosong)"}
      </pre>
    </div>
  );
}
function TextIn({ label, value, onChange, placeholder, dark }) {
  return (
    <label className="block text-sm">
      <span className="block text-xs mb-1 opacity-70">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full rounded-lg border px-3 py-2 outline-none ${
          dark
            ? "bg-gray-900 border-gray-700 text-gray-100 placeholder-gray-500 dark-scroll"
            : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
        }`}
      />
    </label>
  );
}

function TextAreaIn({ label, value, onChange, rows = 10, placeholder, dark }) {
  return (
    <label className="block text-sm">
      <span className="block text-xs mb-1 opacity-70">{label}</span>
      <textarea
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full font-mono rounded-lg border p-2 outline-none resize-y ${
          dark
            ? "bg-gray-900 border-gray-700 text-gray-100 placeholder-gray-500 dark-scroll"
            : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
        }`}
      />
    </label>
  );
}
