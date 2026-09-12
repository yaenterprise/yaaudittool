import express from "express";
import path from "path";
import fs from "fs";
import os from "os";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";

interface LicenseData {
  product_identity: string;
  hardware_id: string;
  device_hostname: string;
  platform: string;
  expires_at: string;
  generated_at: string;
  node_auth: string;
  protocol: string;
  signature: string;
}

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10mb" }));

// Server-side storage path for license persistence
const DATA_DIR = path.join(process.cwd(), "data");
const LICENSE_FILE = path.join(DATA_DIR, "license.json");

function ensureDataDirExists() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// Server-side helper: XOR Decrypt Base64 payload
const xorDecryptBase64 = (b64Str: string, key: string): string => {
  if (!b64Str || !key) return "";
  try {
    const raw = Buffer.from(b64Str.trim(), "base64").toString("binary");
    return Array.from(raw)
      .map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length)))
      .join("");
  } catch (e) {
    return "";
  }
};

// Robust expiry date parser
const parseExpiryDate = (data: any, secretKey?: string): Date | null => {
  if (!data) return null;

  const isValidDate = (d: any): d is Date => {
    return d instanceof Date && !isNaN(d.getTime()) && d.getFullYear() > 2000 && d.getFullYear() < 2100;
  };

  let candidate: any = data;
  if (typeof data === "object" && data !== null) {
    candidate = 
      data.expires_at || 
      data.expiry_date || 
      data.expiration_date || 
      data.expiry || 
      data.expiration || 
      data.valid_until || 
      data.expires || 
      data.expire_time || 
      data.exp || 
      data.enc_expiry || 
      data.enc_expires || 
      data.encrypted_expiry || 
      data.encrypted_expiration ||
      data.expiry_timestamp ||
      data.expire_date ||
      data.date;

    if (!candidate) {
      for (const key of Object.keys(data)) {
        const val = data[key];
        if (typeof val === "string" || typeof val === "number") {
          const tryD = parseExpiryDate(val, secretKey);
          if (tryD && isValidDate(tryD)) return tryD;
        }
      }
    }
  }

  if (!candidate) return null;

  const tryNumeric = (val: any): Date | null => {
    const num = Number(val);
    if (!isNaN(num) && num > 0) {
      const ms = num < 10000000000 ? num * 1000 : num;
      const d = new Date(ms);
      if (isValidDate(d)) return d;
    }
    return null;
  };

  const tryStringDate = (str: string): Date | null => {
    if (!str || typeof str !== "string") return null;
    const trimmed = str.trim();
    if (!trimmed) return null;

    let d = new Date(trimmed);
    if (isValidDate(d)) return d;

    d = new Date(trimmed.replace(" ", "T"));
    if (isValidDate(d)) return d;

    d = new Date(trimmed.replace(/-/g, "/"));
    if (isValidDate(d)) return d;

    return null;
  };

  const tryBase64 = (str: string): Date | null => {
    if (!str || typeof str !== "string") return null;
    try {
      const decoded = Buffer.from(str.trim(), "base64").toString("binary");
      if (decoded && decoded !== str) {
        const dNum = tryNumeric(decoded);
        if (dNum) return dNum;

        const dStr = tryStringDate(decoded);
        if (dStr) return dStr;

        if (decoded.startsWith("{") && decoded.endsWith("}")) {
          try {
            const parsed = JSON.parse(decoded);
            const dParsed = parseExpiryDate(parsed, secretKey);
            if (dParsed) return dParsed;
          } catch {}
        }

        if (decoded.includes("|")) {
          for (const part of decoded.split("|")) {
            const dPart = tryNumeric(part) || tryStringDate(part) || tryBase64(part);
            if (dPart) return dPart;
          }
        }
      }
    } catch {}
    return null;
  };

  const tryXOR = (str: string, key?: string): Date | null => {
    if (!str || typeof str !== "string" || !key) return null;
    try {
      const decrypted = xorDecryptBase64(str, key);
      if (!decrypted) return null;

      const dNum = tryNumeric(decrypted);
      if (dNum) return dNum;

      const dStr = tryStringDate(decrypted);
      if (dStr) return dStr;

      if (decrypted.includes("|")) {
        for (const part of decrypted.split("|")) {
          const dPart = tryNumeric(part) || tryStringDate(part);
          if (dPart) return dPart;
        }
      }
    } catch {}
    return null;
  };

  const valStr = String(candidate);

  const resNum = tryNumeric(candidate);
  if (resNum) return resNum;

  const resStr = tryStringDate(valStr);
  if (resStr) return resStr;

  if (secretKey) {
    const resXOR = tryXOR(valStr, secretKey);
    if (resXOR) return resXOR;
  }

  const resB64 = tryBase64(valStr);
  if (resB64) return resB64;

  return null;
};

// Read saved backend license
function getStoredBackendLicense(): LicenseData | null {
  try {
    ensureDataDirExists();
    if (fs.existsSync(LICENSE_FILE)) {
      const content = fs.readFileSync(LICENSE_FILE, "utf-8");
      const parsed = JSON.parse(content) as LicenseData;
      const expiry = parseExpiryDate(parsed);
      if (expiry && expiry.getTime() > Date.now()) {
        return parsed;
      }
    }
  } catch (e) {
    console.error("Error reading backend license file:", e);
  }
  return null;
}

// Save backend license
function saveBackendLicense(data: LicenseData) {
  ensureDataDirExists();
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(data, null, 2), "utf-8");
}

// Clear backend license
function clearBackendLicense() {
  ensureDataDirExists();
  if (fs.existsSync(LICENSE_FILE)) {
    fs.unlinkSync(LICENSE_FILE);
  }
}

// Helper: Generate unique machine Hardware ID based on network interfaces MAC, CPU model, hostname, platform, and arch
function getSystemHardwareId(): string {
  try {
    const netInterfaces = os.networkInterfaces();
    let macs: string[] = [];
    for (const name of Object.keys(netInterfaces)) {
      const ifaceList = netInterfaces[name];
      if (ifaceList) {
        for (const iface of ifaceList) {
          if (!iface.internal && iface.mac && iface.mac !== "00:00:00:00:00:00") {
            macs.push(iface.mac.toLowerCase());
          }
        }
      }
    }
    macs.sort();

    const cpuModel = os.cpus()?.[0]?.model || "";
    const hostname = os.hostname() || "";
    const platform = os.platform() || "";
    const arch = os.arch() || "";

    const rawString = `${macs.join("-")}|${cpuModel}|${hostname}|${platform}|${arch}`;

    if (rawString.length > 5) {
      const hash = crypto.createHash("sha256").update(rawString).digest("hex").toUpperCase();
      return `${hash.substring(0, 4)}-${hash.substring(4, 8)}-${hash.substring(8, 12)}-${hash.substring(12, 16)}`;
    }
  } catch (e) {
    console.error("Error generating system HWID:", e);
  }
  return "M4Z9-KCRV-HU7A-ZZXP";
}

// API Routes
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// GET /api/system-info - Return unique hardware details for current machine
app.get("/api/system-info", (_req, res) => {
  const hwid = getSystemHardwareId();
  const hostname = os.hostname() || "localhost";
  const plat = os.platform();
  const platformName = plat === "win32" ? "WINDOWS" : plat === "darwin" ? "MACOS" : "LINUX";

  res.json({
    hardwareId: hwid,
    hostname,
    platform: platformName,
    systemTime: new Date().toISOString()
  });
});

// GET /api/license - Get current backend stored license status
app.get("/api/license", (_req, res) => {
  const licenseData = getStoredBackendLicense();
  if (!licenseData) {
    return res.json({
      isLicensed: false,
      licenseData: null,
      message: "No active backend license found or license expired."
    });
  }

  const expDate = parseExpiryDate(licenseData);
  const isValid = expDate ? expDate.getTime() > Date.now() : true;

  res.json({
    isLicensed: isValid,
    licenseData: isValid ? licenseData : null,
    expires_at: expDate ? expDate.toISOString() : licenseData.expires_at,
    systemTime: new Date().toISOString()
  });
});

// POST /api/license/activate - Server-side validation and storage
app.post("/api/license/activate", (req, res) => {
  const systemHwid = getSystemHardwareId();
  const { rawInput, secretKey, hardwareId = systemHwid, hostname = "localhost", platform = "WINDOWS" } = req.body;

  if (!rawInput) {
    return res.status(400).json({ success: false, error: "Unauthorized License" });
  }

  const cleanSecretKey = (secretKey || "").trim();
  if (!cleanSecretKey) {
    return res.status(400).json({ success: false, error: "Unauthorized License" });
  }

  let parsedJson: (LicenseData & { secret_key?: string; app_secret_key?: string }) | null = null;
  let signatureToValidate = rawInput.trim();

  if (rawInput.trim().startsWith("{") && rawInput.trim().endsWith("}")) {
    try {
      parsedJson = JSON.parse(rawInput);
      signatureToValidate = parsedJson?.signature || signatureToValidate;
    } catch (e) {
      return res.status(400).json({ success: false, error: "Unauthorized License" });
    }
  }

  // Decrypt signature using XOR cipher with cleanSecretKey
  const xorDecryptedSig = xorDecryptBase64(signatureToValidate, cleanSecretKey);
  let sigParts = xorDecryptedSig ? xorDecryptedSig.split("|") : [];

  if (sigParts.length < 8) {
    try {
      const plainDecoded = Buffer.from(signatureToValidate, "base64").toString("binary");
      if (plainDecoded.includes("|")) {
        sigParts = plainDecoded.split("|");
      }
    } catch {}
  }

  if (sigParts.length >= 8) {
    const [pProdId, pHwid, pHost, pPlat, pExpAt, pNodeAuth, pProto, pSecretKey] = sigParts;

    // 1. Secret Key Check
    if (pSecretKey !== cleanSecretKey) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }
    if (parsedJson?.secret_key && parsedJson.secret_key !== cleanSecretKey) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 2. Hardware ID Check
    const effectiveHwid = hardwareId || systemHwid;
    if (pHwid !== "GLOBAL" && pHwid !== effectiveHwid && pHwid !== systemHwid) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }
    if (parsedJson?.hardware_id && parsedJson.hardware_id !== "GLOBAL" && parsedJson.hardware_id !== effectiveHwid && parsedJson.hardware_id !== systemHwid) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 3. Product Identity Check
    if (parsedJson?.product_identity && parsedJson.product_identity !== pProdId) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 4. Device Hostname Check (Exact machine match against signature & license)
    const sysHost = (os.hostname() || "localhost").toLowerCase().trim();
    const reqHost = (hostname || "").toLowerCase().trim();
    const sigHost = (pHost || "").toLowerCase().trim();
    const jsonHost = (parsedJson?.device_hostname || "").toLowerCase().trim();

    if (sigHost !== "global" && sigHost !== "*" && sigHost !== reqHost && sigHost !== sysHost) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }
    if (jsonHost && jsonHost !== "global" && jsonHost !== "*" && jsonHost !== reqHost && jsonHost !== sysHost) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }
    if (jsonHost && jsonHost !== sigHost && jsonHost !== "global" && sigHost !== "global" && jsonHost !== "*" && sigHost !== "*") {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 5. Platform Check (Machine match)
    const normPlat = (p: string) => {
      const u = (p || "").toUpperCase().trim();
      return u === "WIN32" ? "WINDOWS" : u === "DARWIN" ? "MACOS" : u;
    };
    const sysPlat = normPlat(os.platform() === "win32" ? "WINDOWS" : os.platform() === "darwin" ? "MACOS" : "LINUX");
    const reqPlat = normPlat(platform);
    const sigPlat = normPlat(pPlat);
    const jsonPlat = normPlat(parsedJson?.platform || "");

    if (sigPlat !== "GLOBAL" && sigPlat !== "*") {
      if (sigPlat !== reqPlat && sigPlat !== sysPlat) {
        return res.status(400).json({
          success: false,
          error: "Unauthorized License"
        });
      }
    }
    if (jsonPlat && jsonPlat !== "GLOBAL" && jsonPlat !== "*") {
      if (jsonPlat !== reqPlat && jsonPlat !== sysPlat) {
        return res.status(400).json({
          success: false,
          error: "Unauthorized License"
        });
      }
    }
    if (jsonPlat && jsonPlat !== sigPlat && jsonPlat !== "GLOBAL" && sigPlat !== "GLOBAL" && jsonPlat !== "*" && sigPlat !== "*") {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 6. Node Auth Check
    if (parsedJson?.node_auth && parsedJson.node_auth !== pNodeAuth) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 7. Protocol Check
    if (parsedJson?.protocol && parsedJson.protocol !== pProto) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    // 8. Expiration Date Check
    const expDate = parseExpiryDate(pExpAt, cleanSecretKey) ||
      parseExpiryDate(parsedJson?.expires_at, cleanSecretKey) ||
      parseExpiryDate(parsedJson, cleanSecretKey);

    if (!expDate || isNaN(expDate.getTime())) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    if (expDate.getTime() <= Date.now()) {
      return res.status(400).json({
        success: false,
        error: "Unauthorized License"
      });
    }

    const licenseObj: LicenseData = {
      product_identity: pProdId || parsedJson?.product_identity || "YA AUDIT TOOL V.0.1",
      hardware_id: pHwid || parsedJson?.hardware_id || hardwareId,
      device_hostname: pHost || parsedJson?.device_hostname || hostname,
      platform: pPlat || parsedJson?.platform || platform,
      expires_at: expDate.toISOString(),
      generated_at: parsedJson?.generated_at || new Date().toISOString(),
      node_auth: pNodeAuth || parsedJson?.node_auth || "0x9047489741",
      protocol: pProto || parsedJson?.protocol || "RBAC-LEVEL-3",
      signature: signatureToValidate
    };

    saveBackendLicense(licenseObj);

    return res.json({
      success: true,
      message: "Valid License",
      licenseData: licenseObj
    });
  } else {
    return res.status(400).json({
      success: false,
      error: "Unauthorized License"
    });
  }
});

// POST /api/license/revoke - Remove backend stored license
app.post("/api/license/revoke", (_req, res) => {
  clearBackendLicense();
  res.json({
    success: true,
    message: "Backend license revoked successfully."
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Backend License Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
