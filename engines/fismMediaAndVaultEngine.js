import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import zlib from "node:zlib";
const execFileAsync = promisify(execFile);
const VAULT_MASTER_SECRET =
  String(process.env.FISM_VAULT_SECRET || "").trim() ||
  crypto.randomBytes(32).toString("hex");
const VAULT_AES_KEY = crypto.scryptSync(VAULT_MASTER_SECRET, "fism-id-vault-salt-v1", 32);
function extractClientIpAndDevice(req, deviceNameOverride) {
  const xff = req.headers["x-forwarded-for"];
  let rawIp = typeof xff === "string" && xff.trim() ? xff.split(",")[0].trim() : Array.isArray(xff) && xff.length > 0 ? String(xff[0]).trim() : req.socket?.remoteAddress || "127.0.0.1";
  if (rawIp === "::1") rawIp = "127.0.0.1";
  if (rawIp.startsWith("::ffff:")) rawIp = rawIp.slice(7);
  const ua = String(req.headers["user-agent"] || "Unknown Client");
  let platformOs = "Linux / Web";
  if (/android/i.test(ua)) platformOs = "Android Mobile";
  else if (/iphone|ipad|ipod/i.test(ua)) platformOs = "Apple iOS";
  else if (/windows/i.test(ua)) platformOs = "Windows PC";
  else if (/mac os x|macintosh/i.test(ua)) platformOs = "Apple macOS";
  else if (/linux/i.test(ua)) platformOs = "Linux Desktop";
  let browser = "FISM App";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";
  else if (/node|undici/i.test(ua)) browser = "API Client";
  const cleanOverride = String(deviceNameOverride || "").trim().slice(0, 120);
  const deviceName = cleanOverride || `${platformOs} (${browser})`;
  return {
    ipAddress: rawIp || "127.0.0.1",
    deviceName,
    platformOs
  };
}
function encryptIdDocumentAes256Gcm(rawBase64OrDataUrl, mimeType = "image/png") {
  let cleanB64 = String(rawBase64OrDataUrl || "").trim();
  let detectedMime = mimeType;
  if (cleanB64.startsWith("data:")) {
    const match = /^data:([^;]+);base64,(.*)$/s.exec(cleanB64);
    if (match) {
      detectedMime = match[1] || mimeType;
      cleanB64 = match[2] || "";
    }
  }
  const plainBuf = Buffer.from(cleanB64, "base64");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", VAULT_AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertextHash = crypto.createHash("sha256").update(encrypted).digest("hex").slice(0, 24);
  return {
    ciphertextBase64: encrypted.toString("base64"),
    ciphertextHash: `sha256:${ciphertextHash}`,
    ivHex: iv.toString("hex"),
    authTagHex: authTag.toString("hex"),
    mimeType: detectedMime
  };
}
function decryptIdDocumentAes256Gcm(ciphertextBase64, ivHex, authTagHex, mimeType = "image/png") {
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const encrypted = Buffer.from(ciphertextBase64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", VAULT_AES_KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return {
    dataUrl: `data:${mimeType};base64,${decrypted.toString("base64")}`,
    byteLength: decrypted.length
  };
}
function sanitizeFfmpegText(input) {
  return String(input || "").replace(/[^a-zA-Z0-9 _.\-@]/g, "").trim().slice(0, 36);
}
function resolveFontFile() {
  const candidates = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}
async function burnFismWatermarkWithFfmpeg(opts) {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "fism-wm-"));
  const fontFile = resolveFontFile();
  const safeAuthor = sanitizeFfmpegText(opts.authorUsername || "fism_creator") || "fism_creator";
  const safeTitleSlug = String(opts.title || opts.postId || "video").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "fism-video";
  const watermarkLabel = `FISM @${safeAuthor}`;
  const outPath = path.join(workDir, "branded_output.mp4");
  try {
    let sourceInputArgs = [];
    let hasInputFile = false;
    const tryWriteUrlAsset = async (rawUrl, kind) => {
      if (!rawUrl || !rawUrl.trim()) return null;
      const u = rawUrl.trim();
      const targetExt = kind === "video" ? ".mp4" : ".img";
      const targetPath = path.join(workDir, `source_${kind}${targetExt}`);
      if (u.startsWith(`data:${kind}/`)) {
        const match = /^data:[^;]+;base64,(.*)$/s.exec(u);
        if (match && match[1]) {
          fs.writeFileSync(targetPath, Buffer.from(match[1], "base64"));
          return targetPath;
        }
      }
      if (u.startsWith("/src/") || u.startsWith("/public/") || u.startsWith("/assets/")) {
        const cleanRel = u.replace(/^\/+/, "");
        const candidates = [
          path.resolve(opts.projectRootDir, "frontend", cleanRel),
          path.resolve(opts.projectRootDir, cleanRel)
        ];
        for (const absCandidate of candidates) {
          if (absCandidate.startsWith(opts.projectRootDir) && fs.existsSync(absCandidate)) {
            fs.copyFileSync(absCandidate, targetPath);
            return targetPath;
          }
        }
      }
      if (/^https?:\/\//i.test(u)) {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 8e3);
          const resp = await fetch(u, { signal: controller.signal });
          clearTimeout(timer);
          if (resp.ok) {
            const ct = String(resp.headers.get("content-type") || "").toLowerCase();
            if (kind === "video" && (ct.includes("video/") || ct.includes("octet-stream")) || kind === "image" && ct.includes("image/")) {
              const ab = await resp.arrayBuffer();
              if (ab.byteLength > 256 && ab.byteLength <= 35 * 1024 * 1024) {
                fs.writeFileSync(targetPath, Buffer.from(ab));
                return targetPath;
              }
            }
          }
        } catch {
        }
      }
      return null;
    };
    const videoFile = await tryWriteUrlAsset(opts.videoUrl, "video");
    if (videoFile) {
      sourceInputArgs = ["-i", videoFile];
      hasInputFile = true;
    } else {
      const thumbFile = await tryWriteUrlAsset(opts.thumbnailUrl, "image") || await tryWriteUrlAsset(opts.videoUrl, "image");
      if (thumbFile) {
        const clipLen = Math.min(8, Math.max(3, Math.round(opts.durationSeconds || 4)));
        sourceInputArgs = ["-loop", "1", "-t", String(clipLen), "-i", thumbFile];
        hasInputFile = true;
      }
    }
    if (!hasInputFile) {
      const dims = opts.isVertical ? "720x1280" : "1280x720";
      const clipLen = Math.min(6, Math.max(3, Math.round(opts.durationSeconds || 4)));
      sourceInputArgs = ["-f", "lavfi", "-i", `color=c=#0F172A:s=${dims}:r=24:d=${clipLen}`];
    }
    const scaleTarget = opts.isVertical ? "scale=720:1280:force_original_aspect_ratio=decrease,pad=720:1280:(ow-iw)/2:(oh-ih)/2:color=#0B0F1A,setsar=1" : "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=#0B0F1A,setsar=1";
    const titleShort = sanitizeFfmpegText(opts.title || "FISM Original") || "FISM Original";
    const vf = [
      scaleTarget,
      // Top-left permanent FISM badge background + crimson brand strip
      "drawbox=x=20:y=20:w=310:h=46:color=black@0.72:t=fill",
      "drawbox=x=20:y=20:w=82:h=46:color=#E53935@0.95:t=fill",
      `drawtext=fontfile=${fontFile}:text='FISM':fontcolor=white:fontsize=22:x=32:y=33`,
      `drawtext=fontfile=${fontFile}:text='@${safeAuthor}':fontcolor=white:fontsize=18:x=114:y=34`,
      // Bottom-right permanent anti-reupload promotion stamp
      "drawbox=x=w-290:y=h-56:w=270:h=38:color=black@0.74:t=fill",
      `drawtext=fontfile=${fontFile}:text='FISM APP  fism.app':fontcolor=#FFB300:fontsize=16:x=w-274:y=h-44`,
      // Subtle lower-left video title attribution
      "drawbox=x=20:y=h-56:w=320:h=38:color=black@0.55:t=fill",
      `drawtext=fontfile=${fontFile}:text='${titleShort}':fontcolor=white@0.92:fontsize=14:x=32:y=h-43`
    ].join(",");
    await execFileAsync(
      "ffmpeg",
      [
        "-y",
        ...sourceInputArgs,
        "-vf",
        vf,
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-crf",
        "24",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        "-b:a",
        "96k",
        "-movflags",
        "+faststart",
        "-shortest",
        outPath
      ],
      { timeout: 3e4 }
    );
    const buffer = fs.readFileSync(outPath);
    return {
      buffer,
      filename: `FISM_${safeTitleSlug}_branded.mp4`,
      watermarkLabel,
      engine: "FFmpeg 4.4.2 H.264 Permanent Burn-In"
    };
  } finally {
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
    }
  }
}
const CRC32_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
    }
    tbl[i] = c >>> 0;
  }
  return tbl;
})();
function crc32(buf) {
  let c = 4294967295;
  for (let i = 0; i < buf.length; i++) {
    c = CRC32_TABLE[(c ^ buf[i]) & 255] ^ c >>> 8;
  }
  return (c ^ 4294967295) >>> 0;
}
function buildBackupZipArchive(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const now = /* @__PURE__ */ new Date();
  const dosTime = (now.getHours() & 31) << 11 | (now.getMinutes() & 63) << 5 | now.getSeconds() >> 1 & 31;
  const dosDate = (Math.max(1980, now.getFullYear()) - 1980 & 127) << 9 | (now.getMonth() + 1 & 15) << 5 | now.getDate() & 31;
  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.relativePath.replace(/^\/+/, ""), "utf8");
    const rawData = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, "utf8");
    const compressed = zlib.deflateRawSync(rawData);
    const sum = crc32(rawData);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(67324752, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(2048, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(sum, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(rawData.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localParts.push(localHeader, nameBuf, compressed);
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(33639248, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(2048, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(sum, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(rawData.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }
  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(101010256, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirBuf, eocd]);
}
export {
  buildBackupZipArchive,
  burnFismWatermarkWithFfmpeg,
  decryptIdDocumentAes256Gcm,
  encryptIdDocumentAes256Gcm,
  extractClientIpAndDevice
};
