import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import process from "node:process";

const artifacts = {
    "linux-x64": {
        url: "https://raw.githubusercontent.com/imagemin/optipng-bin/v5.1.0/vendor/linux/x64/optipng",
        sha256: "12ef97e434641350a92c1ac08d1afa439ea9acd3c5af791fbeddc120c9efdf55",
    },
};
const key = `${process.platform}-${process.arch}`;
const artifact = artifacts[key];
if (!artifact) throw new Error(`No reviewed optipng artifact for ${key}`);

const destination = path.resolve("node_modules/optipng-bin/vendor/optipng");
const temporary = `${destination}.download`;
fs.mkdirSync(path.dirname(destination), { recursive: true });

function digest(file) {
    return crypto
        .createHash("sha256")
        .update(fs.readFileSync(file))
        .digest("hex");
}

async function download(url, redirects = 0) {
    if (redirects > 3) throw new Error("Too many optipng download redirects");
    await new Promise((resolve, reject) => {
        const request = https.get(
            url,
            { headers: { "User-Agent": "staticdeploy-toolchain-provisioner" } },
            (response) => {
                if (
                    response.statusCode >= 300 &&
                    response.statusCode < 400 &&
                    response.headers.location
                ) {
                    response.resume();
                    const next = new URL(response.headers.location, url);
                    if (next.protocol !== "https:")
                        return reject(
                            new Error("Refusing non-HTTPS optipng redirect")
                        );
                    return resolve(download(next, redirects + 1));
                }
                if (response.statusCode !== 200) {
                    response.resume();
                    return reject(
                        new Error(
                            `optipng download returned HTTP ${response.statusCode}`
                        )
                    );
                }
                const output = fs.createWriteStream(temporary, {
                    flags: "wx",
                    mode: 0o755,
                });
                response.pipe(output);
                output.on("finish", () => output.close(resolve));
                output.on("error", reject);
            }
        );
        request.on("error", reject);
    });
}

try {
    if (
        !fs.existsSync(destination) ||
        digest(destination) !== artifact.sha256
    ) {
        fs.rmSync(temporary, { force: true });
        await download(artifact.url);
        const actual = digest(temporary);
        if (actual !== artifact.sha256)
            throw new Error(`optipng checksum mismatch: ${actual}`);
        fs.renameSync(temporary, destination);
    }
    if (digest(destination) !== artifact.sha256)
        throw new Error("Provisioned optipng checksum mismatch");
    fs.chmodSync(destination, 0o755);
    console.log(
        `Provisioned reviewed optipng artifact for ${key} (${artifact.sha256}).`
    );
} finally {
    fs.rmSync(temporary, { force: true });
}
