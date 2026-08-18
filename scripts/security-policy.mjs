import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import parseSpdx from "spdx-expression-parse";

const SCHEMA_VERSION = 1;
const MAX_REPORT_AGE_MS = 2 * 60 * 60 * 1000;
const MAX_DATABASE_AGE_MS = 24 * 60 * 60 * 1000;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const validDatabaseIdentity = (value) => {
    if (typeof value !== "string") return false;
    const separator = value.indexOf("|");
    if (separator <= 0 || !/^v[0-9.]+$/.test(value.slice(0, separator)))
        return false;
    try {
        const source = new URL(value.slice(separator + 1));
        return (
            source.protocol === "https:" &&
            DIGEST.test(source.searchParams.get("checksum") || "")
        );
    } catch {
        return false;
    }
};
const requiredTypes = [
    "dependency-vulnerabilities",
    "sast",
    "secrets",
    "image-vulnerabilities",
    "source-sbom",
    "image-sbom",
    "license-inventory",
];
const blockingSeverities = new Set(["critical", "high", "unknown"]);
const scannerContracts = {
    "dependency-vulnerabilities": {
        name: "grype",
        version: "0.117.0",
        identity:
            "anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253",
        exits: [0],
        database: true,
    },
    "image-vulnerabilities": {
        name: "grype",
        version: "0.117.0",
        identity:
            "anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253",
        exits: [0],
        database: true,
    },
    "source-sbom": {
        name: "staticdeploy-lock-sbom",
        version: "1",
        identity: "repository:scripts/security-policy.mjs#lock-sbom-v1",
        exits: [0],
        rules: true,
    },
    "image-sbom": {
        name: "syft",
        version: "1.51.0",
        identity:
            "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
        exits: [0],
    },
    sast: {
        name: "semgrep",
        version: "1.97.0",
        identity:
            "returntocorp/semgrep@sha256:a265d09a9ca712e6624aca09056304ce4314a695b7028d65c041dd53fd44c700",
        exits: [0, 1],
        rules: true,
    },
    secrets: {
        name: "trufflehog",
        version: "3.97.0",
        identity:
            "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
        exits: [0, 183],
        rules: true,
        expectedRulesetDigest:
            "sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
    },
    "license-inventory": {
        name: "yarn-info",
        version: "4.18.0",
        identity: "yarn@npm:4.18.0",
        exits: [0],
        rules: true,
    },
};

const fail = (message) => {
    throw new Error(message);
};
const readText = (file) => {
    const text = fs.readFileSync(file, "utf8");
    if (!text.trim()) fail(`Required report is empty: ${file}`);
    return text;
};
const readJson = (file) => {
    try {
        return JSON.parse(readText(file));
    } catch (error) {
        fail(`Malformed JSON in ${file}: ${error.message}`);
    }
};
const writeJson = (file, value) =>
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
        flag: "wx",
        mode: 0o600,
    });
const sha256File = (file) =>
    `sha256:${createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`;
const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const asArray = (value, field) => {
    if (!Array.isArray(value)) fail(`${field} must be an array`);
    return value;
};
const exactKeys = (value, keys, field) => {
    if (!value || typeof value !== "object" || Array.isArray(value))
        fail(`${field} must be an object`);
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected))
        fail(`${field} has unexpected or missing fields`);
};
const iso = (value, field) => {
    if (
        typeof value !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)
    )
        fail(`${field} must be a strict RFC3339 UTC timestamp`);
    const time = Date.parse(value);
    if (
        !Number.isFinite(time) ||
        new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)
    )
        fail(`${field} must be a valid RFC3339 UTC timestamp`);
    return time;
};
const parseNdjson = (text, source) =>
    text
        .split(/\r?\n/)
        .filter((line) => line.trim())
        .map((line, index) => {
            try {
                return JSON.parse(line);
            } catch (error) {
                fail(
                    `${source} line ${index + 1} is malformed: ${error.message}`
                );
            }
        });

function validateSubject(value) {
    exactKeys(
        value,
        [
            "schemaVersion",
            "commit",
            "lockDigest",
            "imageConfigDigest",
            "imageManifestDigest",
            "workflow",
        ],
        "subject"
    );
    if (
        value.schemaVersion !== SCHEMA_VERSION ||
        !/^[a-f0-9]{40}$/.test(value.commit)
    )
        fail("Invalid subject schema or commit");
    if (
        !DIGEST.test(value.lockDigest) ||
        !DIGEST.test(value.imageConfigDigest || "") ||
        value.imageManifestDigest !== null
    )
        fail(
            "Subject requires exact lock/image config digests and an explicit null manifest digest for this non-publishing local build"
        );
    exactKeys(
        value.workflow,
        ["repository", "runId", "runAttempt", "eventName", "ref"],
        "subject.workflow"
    );
    for (const field of [
        "repository",
        "runId",
        "runAttempt",
        "eventName",
        "ref",
    ])
        if (typeof value.workflow[field] !== "string" || !value.workflow[field])
            fail(`subject.workflow.${field} is required`);
    return value;
}

function subject(output, imageConfigDigest = null) {
    const commit = process.env.SECURITY_COMMIT || git("rev-parse", "HEAD");
    if (!/^[a-f0-9]{40}$/.test(commit))
        fail("Subject commit must be a full SHA");
    if (!DIGEST.test(imageConfigDigest || ""))
        fail("Image config digest must be sha256:<64 lowercase hex>");
    writeJson(output, {
        schemaVersion: SCHEMA_VERSION,
        commit,
        lockDigest: sha256File("yarn.lock"),
        imageConfigDigest,
        imageManifestDigest: null,
        workflow: {
            repository: process.env.GITHUB_REPOSITORY || "local/staticdeploy",
            runId: process.env.GITHUB_RUN_ID || "local",
            runAttempt: process.env.GITHUB_RUN_ATTEMPT || "1",
            eventName: process.env.GITHUB_EVENT_NAME || "local",
            ref:
                process.env.GITHUB_REF ||
                git("symbolic-ref", "--short", "HEAD"),
        },
    });
}

function normalizeLicenseRecords(records) {
    if (!records.length) fail("License inventory is empty");
    return records.map((record, index) => {
        const locator = record?.value;
        const version = record?.children?.Version;
        const license = record?.children?.Manifest?.License;
        if (typeof locator !== "string" || typeof version !== "string")
            fail(`License record ${index + 1} lacks component/version`);
        return {
            component: locator.replace(/@(?:npm|workspace|patch):.*$/, ""),
            locator,
            version,
            scope: locator.includes("@workspace:") ? "workspace" : "resolved",
            spdxExpression:
                typeof license === "string" && license.trim()
                    ? license.trim()
                    : "NOASSERTION",
        };
    });
}

function sanitizeSourceSbom(payload) {
    exactKeys(
        payload,
        ["bomFormat", "specVersion", "version", "components"],
        "source CycloneDX SBOM"
    );
    if (
        payload.bomFormat !== "CycloneDX" ||
        payload.specVersion !== "1.6" ||
        payload.version !== 1
    )
        fail("Source SBOM has an unsupported CycloneDX schema");
    const components = asArray(
        payload.components,
        "source CycloneDX components"
    ).map((component, index) => {
        exactKeys(
            component,
            ["type", "name", "version", "purl", "bom-ref", "licenses"],
            `source CycloneDX component ${index + 1}`
        );
        exactKeys(
            component.licenses?.[0],
            ["expression"],
            `source CycloneDX component ${index + 1} license`
        );
        if (
            !["application", "library"].includes(component.type) ||
            typeof component.name !== "string" ||
            !component.name ||
            typeof component.version !== "string" ||
            !component.version ||
            typeof component.purl !== "string" ||
            component["bom-ref"] !== component.purl ||
            component.licenses.length !== 1 ||
            typeof component.licenses[0].expression !== "string" ||
            !component.licenses[0].expression
        )
            fail(`Source CycloneDX component ${index + 1} is malformed`);
        return component;
    });
    if (
        !components.length ||
        new Set(components.map((item) => item.purl)).size !== components.length
    )
        fail("Source CycloneDX components must be non-empty and unique");
    return {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components,
    };
}

function sanitizeImageSbom(payload) {
    if (
        !String(payload?.spdxVersion || "").startsWith("SPDX-") ||
        !Array.isArray(payload?.packages)
    )
        fail("Image SBOM has an invalid SPDX schema");
    let described = Array.isArray(payload.documentDescribes)
        ? payload.documentDescribes
        : [];
    if (!described.length) {
        const inferred = payload.packages.find((item) =>
            String(item?.SPDXID || "").startsWith("SPDXRef-DocumentRoot-Image-")
        );
        if (inferred) described = [inferred.SPDXID];
    }
    if (described.length !== 1 || typeof described[0] !== "string")
        fail("Image SPDX must identify one document root");
    const packages = payload.packages.map((component, index) => {
        const externalRefs = asArray(
            component?.externalRefs || [],
            `image SPDX package ${index + 1} externalRefs`
        )
            .filter(
                (reference) =>
                    reference?.referenceType === "purl" &&
                    typeof reference.referenceLocator === "string"
            )
            .map((reference) => ({
                referenceType: "purl",
                referenceLocator: reference.referenceLocator,
            }));
        const value = {
            name: component?.name,
            SPDXID: component?.SPDXID,
            versionInfo: component?.versionInfo || "NOASSERTION",
            licenseConcluded: component?.licenseConcluded || "NOASSERTION",
            licenseDeclared: component?.licenseDeclared || "NOASSERTION",
            externalRefs,
        };
        if (
            typeof value.name !== "string" ||
            !value.name ||
            typeof value.SPDXID !== "string" ||
            !value.SPDXID ||
            typeof value.versionInfo !== "string" ||
            typeof value.licenseConcluded !== "string" ||
            typeof value.licenseDeclared !== "string"
        )
            fail(`Image SPDX package ${index + 1} is malformed`);
        return value;
    });
    if (!packages.some((item) => item.SPDXID === described[0]))
        fail("Image SPDX document root is absent from packages");
    return {
        spdxVersion: payload.spdxVersion,
        name: String(payload.name || ""),
        documentNamespace: String(payload.documentNamespace || ""),
        documentDescribes: described,
        packages,
    };
}

function sanitizeSemgrep(payload) {
    if (!Array.isArray(payload?.results) || !Array.isArray(payload?.errors))
        fail("Semgrep output has an invalid schema");
    if (payload.errors.length) fail("Semgrep reported scan or parse errors");
    return {
        results: payload.results.map((result, index) => {
            const value = {
                checkId: result?.check_id,
                path: result?.path,
                startLine: result?.start?.line,
                startColumn: result?.start?.col,
                endLine: result?.end?.line,
                endColumn: result?.end?.col,
                severity: result?.extra?.severity,
            };
            if (
                typeof value.checkId !== "string" ||
                typeof value.path !== "string" ||
                !Number.isInteger(value.startLine) ||
                !Number.isInteger(value.startColumn) ||
                !Number.isInteger(value.endLine) ||
                !Number.isInteger(value.endColumn) ||
                !["ERROR", "WARNING", "INFO"].includes(value.severity)
            )
                fail(`Semgrep result ${index + 1} is malformed`);
            return value;
        }),
    };
}

function sanitizeSecrets(payload) {
    exactKeys(
        payload,
        ["schemaVersion", "scanner", "findings"],
        "secret payload"
    );
    if (payload.schemaVersion !== 1 || payload.scanner !== "trufflehog")
        fail("Secret payload has an invalid schema");
    return {
        findings: asArray(payload.findings, "secret findings").map(
            (finding, index) => {
                exactKeys(
                    finding,
                    ["detector", "status", "source"],
                    `secret finding ${index + 1}`
                );
                exactKeys(
                    finding.source,
                    ["commit", "file", "line"],
                    `secret finding ${index + 1}.source`
                );
                if (
                    typeof finding.detector !== "string" ||
                    !["verified", "unknown"].includes(finding.status) ||
                    !/^[a-f0-9]{40}$/.test(finding.source.commit) ||
                    typeof finding.source.file !== "string" ||
                    !finding.source.file ||
                    !Number.isInteger(finding.source.line) ||
                    finding.source.line < 0
                )
                    fail(`Secret finding ${index + 1} is malformed`);
                return finding;
            }
        ),
    };
}

function sanitizeGrype(payload, type) {
    if (!Array.isArray(payload?.matches) || !payload?.source?.target)
        fail("Grype output has an invalid schema");
    const target = {};
    if (typeof payload.source.target === "string")
        target.userInput = payload.source.target;
    else {
        if (typeof payload.source.target.imageID === "string")
            target.imageID = payload.source.target.imageID;
        if (typeof payload.source.target.userInput === "string")
            target.userInput = payload.source.target.userInput;
    }
    return {
        target,
        matches: payload.matches.map((match, index) => {
            const finding = {
                id: match?.vulnerability?.id,
                severity: match?.vulnerability?.severity,
                aliases: (match?.relatedVulnerabilities || []).map(
                    (item) => item?.id
                ),
                component: match?.artifact?.name,
                version: match?.artifact?.version,
                locations: (match?.artifact?.locations || []).map(
                    (item) => item?.path
                ),
            };
            if (
                typeof finding.id !== "string" ||
                typeof finding.severity !== "string" ||
                typeof finding.component !== "string" ||
                typeof finding.version !== "string" ||
                !finding.aliases.every((item) => typeof item === "string") ||
                !finding.locations.every((item) => typeof item === "string")
            )
                fail(`${type} Grype match ${index + 1} is malformed`);
            return finding;
        }),
    };
}

function record(type, rawPath, outputPath) {
    const contract = scannerContracts[type];
    if (!contract) fail(`Unknown report type: ${type}`);
    const subjectReport = validateSubject(
        readJson(
            process.env.SECURITY_SUBJECT ||
                path.join(path.dirname(outputPath), "subject.json")
        )
    );
    const raw = readText(rawPath);
    let payload;
    if (type === "license-inventory")
        payload = {
            components: normalizeLicenseRecords(parseNdjson(raw, rawPath)),
        };
    else {
        const parsed = readJson(rawPath);
        if (type === "sast") payload = sanitizeSemgrep(parsed);
        else if (type === "secrets") payload = sanitizeSecrets(parsed);
        else if (
            ["dependency-vulnerabilities", "image-vulnerabilities"].includes(
                type
            )
        )
            payload = sanitizeGrype(parsed, type);
        else if (type === "source-sbom") payload = sanitizeSourceSbom(parsed);
        else if (type === "image-sbom") payload = sanitizeImageSbom(parsed);
        else fail(`No sanitizer exists for ${type}`);
    }
    const startedAt = process.env.SCANNER_STARTED_AT;
    const completedAt = process.env.SCANNER_COMPLETED_AT;
    iso(startedAt, "SCANNER_STARTED_AT");
    iso(completedAt, "SCANNER_COMPLETED_AT");
    const exitCode = Number(process.env.SCANNER_EXIT_CODE);
    if (!Number.isInteger(exitCode) || !contract.exits.includes(exitCode))
        fail(
            `${type} scanner failed with exit ${process.env.SCANNER_EXIT_CODE}`
        );
    if (process.env.SCANNER_COMPLETE !== "true")
        fail(`${type} scanner is incomplete`);
    if (
        process.env.SCANNER_NAME !== contract.name ||
        process.env.SCANNER_VERSION !== contract.version ||
        process.env.SCANNER_IDENTITY !== contract.identity
    )
        fail(`${type} scanner identity does not match the pinned contract`);
    const rulesetDigest = process.env.SCANNER_RULESET_DIGEST || null;
    if (contract.rules && !DIGEST.test(rulesetDigest || ""))
        fail(`${type} requires an immutable ruleset digest`);
    if (
        contract.expectedRulesetDigest &&
        rulesetDigest !== contract.expectedRulesetDigest
    )
        fail(`${type} ruleset does not match the pinned contract`);
    const databaseUpdatedAt = process.env.SCANNER_DATABASE_UPDATED_AT || null;
    const databaseValid = process.env.SCANNER_DATABASE_VALID === "true";
    const databaseIdentity = process.env.SCANNER_DATABASE_IDENTITY || null;
    if (contract.database) {
        iso(databaseUpdatedAt, `${type} database timestamp`);
        if (!databaseValid || !validDatabaseIdentity(databaseIdentity))
            fail(`${type} database identity or validity is invalid`);
    }
    const inputDigest = process.env.SCANNER_INPUT_DIGEST || null;
    if (
        ["dependency-vulnerabilities", "image-vulnerabilities"].includes(
            type
        ) &&
        !DIGEST.test(inputDigest || "")
    )
        fail(`${type} requires an exact input digest`);
    writeJson(outputPath, {
        schemaVersion: SCHEMA_VERSION,
        type,
        subject: subjectReport,
        scanner: {
            name: contract.name,
            version: contract.version,
            identity: contract.identity,
            rulesetDigest,
            databaseUpdatedAt,
            databaseValid: contract.database ? databaseValid : null,
            databaseIdentity: contract.database ? databaseIdentity : null,
            inputDigest,
        },
        startedAt,
        completedAt,
        exitCode,
        complete: true,
        rawDigest: sha256File(rawPath),
        payload,
    });
}

function validateEnvelope(report, type, subjectReport, now) {
    exactKeys(
        report,
        [
            "schemaVersion",
            "type",
            "subject",
            "scanner",
            "startedAt",
            "completedAt",
            "exitCode",
            "complete",
            "rawDigest",
            "payload",
        ],
        type
    );
    if (report.schemaVersion !== SCHEMA_VERSION || report.type !== type)
        fail(`${type} has an unsupported schema/type`);
    if (JSON.stringify(report.subject) !== JSON.stringify(subjectReport))
        fail(`${type} identifies the wrong exact subject`);
    if (report.complete !== true || !Number.isInteger(report.exitCode))
        fail(`${type} scanner is incomplete`);
    if (!DIGEST.test(report.rawDigest || ""))
        fail(`${type} has an invalid raw digest`);
    const contract = scannerContracts[type];
    exactKeys(
        report.scanner,
        [
            "name",
            "version",
            "identity",
            "rulesetDigest",
            "databaseUpdatedAt",
            "databaseValid",
            "databaseIdentity",
            "inputDigest",
        ],
        `${type}.scanner`
    );
    if (
        report.scanner.name !== contract.name ||
        report.scanner.version !== contract.version ||
        report.scanner.identity !== contract.identity ||
        !contract.exits.includes(report.exitCode)
    )
        fail(`${type} scanner contract mismatch`);
    if (contract.rules && !DIGEST.test(report.scanner.rulesetDigest || ""))
        fail(`${type} ruleset digest is invalid`);
    if (
        contract.expectedRulesetDigest &&
        report.scanner.rulesetDigest !== contract.expectedRulesetDigest
    )
        fail(`${type} ruleset does not match the pinned contract`);
    const started = iso(report.startedAt, `${type}.startedAt`);
    const completed = iso(report.completedAt, `${type}.completedAt`);
    if (
        completed < started ||
        now - completed > MAX_REPORT_AGE_MS ||
        completed > now + 60_000
    )
        fail(`${type} is stale or has invalid timestamps`);
    if (contract.database) {
        const updated = iso(
            report.scanner.databaseUpdatedAt,
            `${type}.databaseUpdatedAt`
        );
        if (
            report.scanner.databaseValid !== true ||
            !validDatabaseIdentity(report.scanner.databaseIdentity) ||
            updated > now ||
            now - updated > MAX_DATABASE_AGE_MS
        )
            fail(
                `${type} vulnerability database is stale, future-dated, or invalid`
            );
        if (!DIGEST.test(report.scanner.inputDigest || ""))
            fail(`${type} lacks an input digest`);
    }
    if (type === "sast") {
        const expected = sha256File("config/semgrep.yml");
        if (report.scanner.rulesetDigest !== expected)
            fail("SAST ruleset digest does not match config/semgrep.yml");
    }
    if (
        ["license-inventory", "source-sbom"].includes(type) &&
        report.scanner.rulesetDigest !== sha256File("yarn.lock")
    )
        fail(`${type} does not identify the exact lockfile`);
}

function validateSanitizedPayloads(reports) {
    exactKeys(reports.sast.payload, ["results"], "SAST payload");
    for (const [index, result] of asArray(
        reports.sast.payload.results,
        "SAST results"
    ).entries()) {
        exactKeys(
            result,
            [
                "checkId",
                "path",
                "startLine",
                "startColumn",
                "endLine",
                "endColumn",
                "severity",
            ],
            `SAST result ${index + 1}`
        );
        if (
            typeof result.checkId !== "string" ||
            typeof result.path !== "string" ||
            !Number.isInteger(result.startLine) ||
            !Number.isInteger(result.startColumn) ||
            !Number.isInteger(result.endLine) ||
            !Number.isInteger(result.endColumn) ||
            !["ERROR", "WARNING", "INFO"].includes(result.severity)
        )
            fail(`SAST result ${index + 1} is malformed`);
    }
    exactKeys(reports.secrets.payload, ["findings"], "secret payload");
    for (const type of [
        "dependency-vulnerabilities",
        "image-vulnerabilities",
    ]) {
        exactKeys(
            reports[type].payload,
            ["target", "matches"],
            `${type} payload`
        );
        if (
            !reports[type].payload.target ||
            typeof reports[type].payload.target !== "object" ||
            Array.isArray(reports[type].payload.target) ||
            Object.keys(reports[type].payload.target).some(
                (key) => !["imageID", "userInput"].includes(key)
            ) ||
            Object.values(reports[type].payload.target).some(
                (value) => typeof value !== "string"
            )
        )
            fail(`${type} target is malformed`);
        for (const [index, match] of asArray(
            reports[type].payload.matches,
            `${type} matches`
        ).entries()) {
            exactKeys(
                match,
                [
                    "id",
                    "severity",
                    "aliases",
                    "component",
                    "version",
                    "locations",
                ],
                `${type} match ${index + 1}`
            );
            if (
                typeof match.id !== "string" ||
                typeof match.severity !== "string" ||
                typeof match.component !== "string" ||
                typeof match.version !== "string" ||
                !Array.isArray(match.aliases) ||
                !match.aliases.every((item) => typeof item === "string") ||
                !Array.isArray(match.locations) ||
                !match.locations.every((item) => typeof item === "string")
            )
                fail(`${type} match ${index + 1} is malformed`);
        }
    }
    exactKeys(
        reports["license-inventory"].payload,
        ["components"],
        "license inventory payload"
    );
    for (const [index, component] of asArray(
        reports["license-inventory"].payload.components,
        "license components"
    ).entries()) {
        exactKeys(
            component,
            ["component", "locator", "version", "scope", "spdxExpression"],
            `license component ${index + 1}`
        );
        for (const field of [
            "component",
            "locator",
            "version",
            "scope",
            "spdxExpression",
        ])
            if (typeof component[field] !== "string" || !component[field])
                fail(`License component ${index + 1} lacks ${field}`);
    }
    sanitizeSourceSbom(reports["source-sbom"].payload);
    sanitizeImageSbom(reports["image-sbom"].payload);
}

function normalizeSeverity(value) {
    const severity = String(value || "unknown").toLowerCase();
    if (severity === "moderate") return "medium";
    if (["negligible", "info"].includes(severity)) return "low";
    return ["critical", "high", "medium", "low"].includes(severity)
        ? severity
        : "unknown";
}

function grypeFindings(report, scope) {
    return asArray(
        report.payload?.matches,
        `${scope} vulnerability matches`
    ).map((item, index) => ({
        source: "grype",
        id: item.id || `unknown-${index}`,
        aliases: [...new Set(item.aliases || [])].sort(),
        component: item.component || "unknown",
        version: item.version || "unknown",
        path: (item.locations || []).join(",") || scope,
        severity: normalizeSeverity(item.severity),
        scope,
    }));
}
function sastFindings(report) {
    return asArray(report.payload?.results, "Semgrep results").map(
        (result, index) => ({
            source: "semgrep",
            id: result.checkId || `unknown-${index}`,
            aliases: [],
            component: result.path || "unknown",
            version: "source",
            path: `${result.path || "unknown"}:${result.startLine || 0}:${result.startColumn || 0}`,
            severity:
                result.severity === "ERROR"
                    ? "high"
                    : result.severity === "WARNING"
                      ? "medium"
                      : result.severity === "INFO"
                        ? "low"
                        : "unknown",
            scope: "source",
        })
    );
}

function validateExceptions(policy, subjectReport, now) {
    exactKeys(
        policy,
        ["schemaVersion", "exceptions"],
        "vulnerability exception policy"
    );
    if (policy.schemaVersion !== SCHEMA_VERSION)
        fail("Unsupported vulnerability exception schema");
    const seen = new Set();
    return asArray(policy.exceptions, "vulnerability exceptions").map(
        (item, index) => {
            const required = [
                "id",
                "findingId",
                "aliases",
                "component",
                "version",
                "path",
                "scope",
                "severity",
                "subjectCommit",
                "imageConfigDigest",
                "owner",
                "securityApprover",
                "releaseOwnerApprover",
                "reviewReference",
                "remediationTracker",
                "riskRationale",
                "compensatingControls",
                "createdAt",
                "expiresAt",
            ];
            exactKeys(item, required, `exception ${index + 1}`);
            if (typeof item.id !== "string" || !item.id || seen.has(item.id))
                fail("Exception IDs must be non-empty and unique");
            seen.add(item.id);
            if (/[*?]/.test(JSON.stringify(item)))
                fail(`Exception ${item.id} contains a wildcard`);
            for (const field of [
                "findingId",
                "component",
                "version",
                "path",
                "scope",
                "severity",
                "subjectCommit",
                "owner",
                "securityApprover",
                "reviewReference",
                "remediationTracker",
                "riskRationale",
                "compensatingControls",
            ])
                if (typeof item[field] !== "string" || !item[field])
                    fail(`Exception ${item.id} lacks ${field}`);
            if (
                !Array.isArray(item.aliases) ||
                !item.aliases.every((value) => typeof value === "string") ||
                new Set(item.aliases).size !== item.aliases.length
            )
                fail(`Exception ${item.id} aliases are invalid`);
            if (
                !blockingSeverities.has(item.severity) ||
                item.subjectCommit !== subjectReport.commit
            )
                fail(`Exception ${item.id} has wrong severity or subject`);
            if (item.scope === "image") {
                if (item.imageConfigDigest !== subjectReport.imageConfigDigest)
                    fail(`Exception ${item.id} has wrong image config digest`);
            } else if (item.imageConfigDigest !== null)
                fail(
                    `Exception ${item.id} must not carry an image config digest`
                );
            if (
                item.severity === "critical" &&
                (typeof item.releaseOwnerApprover !== "string" ||
                    !item.releaseOwnerApprover)
            )
                fail(
                    `Critical exception ${item.id} lacks release-owner approval`
                );
            if (
                item.severity !== "critical" &&
                item.releaseOwnerApprover !== null
            )
                fail(
                    `Non-critical exception ${item.id} has an unexpected release-owner approval`
                );
            const created = iso(
                item.createdAt,
                `exception ${item.id}.createdAt`
            );
            const expiry = iso(
                item.expiresAt,
                `exception ${item.id}.expiresAt`
            );
            const max = item.severity === "critical" ? 7 : 30;
            if (
                created > now ||
                expiry <= now ||
                expiry <= created ||
                expiry - created > max * 86400000
            )
                fail(`Exception ${item.id} is invalid or expired`);
            return item;
        }
    );
}

function exactException(finding, subjectReport, exceptions) {
    return exceptions.find(
        (item) =>
            item.findingId === finding.id &&
            JSON.stringify([...item.aliases].sort()) ===
                JSON.stringify([...finding.aliases].sort()) &&
            item.component === finding.component &&
            item.version === finding.version &&
            item.path === finding.path &&
            item.scope === finding.scope &&
            item.severity === finding.severity &&
            item.subjectCommit === subjectReport.commit &&
            (finding.scope !== "image" ||
                item.imageConfigDigest === subjectReport.imageConfigDigest)
    );
}

function collectLicenseIds(node, output = new Set()) {
    if (node?.license) output.add(node.license + (node.plus ? "+" : ""));
    else if (node?.left && node?.right) {
        collectLicenseIds(node.left, output);
        collectLicenseIds(node.right, output);
    } else fail("Malformed SPDX expression tree");
    return output;
}
function hasOr(node) {
    return (
        node?.conjunction === "or" ||
        (node?.left && (hasOr(node.left) || hasOr(node.right)))
    );
}
function hasException(node) {
    return (
        typeof node?.exception === "string" ||
        (node?.left && (hasException(node.left) || hasException(node.right)))
    );
}
function canonicalSpdx(node) {
    if (node?.license)
        return `${node.license}${node.plus ? "+" : ""}${node.exception ? ` WITH ${node.exception}` : ""}`;
    if (node?.left && node?.right && ["and", "or"].includes(node.conjunction))
        return `(${canonicalSpdx(node.left)} ${node.conjunction.toUpperCase()} ${canonicalSpdx(node.right)})`;
    fail("Malformed SPDX expression tree");
}
function offeredOrBranches(node) {
    if (node?.conjunction === "or")
        return [
            ...offeredOrBranches(node.left),
            ...offeredOrBranches(node.right),
        ];
    return [node];
}
function validateObligationEvidence(evidence, field) {
    exactKeys(
        evidence,
        [
            "obligationsComplete",
            "evidencePath",
            "evidenceDigest",
            "reviewReference",
            "missingReason",
        ],
        field
    );
    if (
        typeof evidence.reviewReference !== "string" ||
        !evidence.reviewReference
    )
        fail(`${field} lacks a review reference`);
    if (evidence.obligationsComplete === true) {
        if (
            typeof evidence.evidencePath !== "string" ||
            !evidence.evidencePath.startsWith(
                "docs/security/license-evidence/"
            ) ||
            path.isAbsolute(evidence.evidencePath) ||
            path.normalize(evidence.evidencePath) !== evidence.evidencePath ||
            !DIGEST.test(evidence.evidenceDigest || "") ||
            evidence.missingReason !== null ||
            !fs.existsSync(evidence.evidencePath) ||
            sha256File(evidence.evidencePath) !== evidence.evidenceDigest
        )
            fail(`${field} lacks a retained artifact with its exact digest`);
    } else if (
        evidence.obligationsComplete !== false ||
        evidence.evidencePath !== null ||
        evidence.evidenceDigest !== null ||
        typeof evidence.missingReason !== "string" ||
        !evidence.missingReason
    )
        fail(`${field} must report its missing obligation artifact`);
    return evidence;
}
function validateLicensePolicy(policy) {
    exactKeys(
        policy,
        [
            "schemaVersion",
            "allowedSpdx",
            "obligationEvidence",
            "reviewedExpressions",
        ],
        "license policy"
    );
    if (policy.schemaVersion !== SCHEMA_VERSION)
        fail("Unsupported license policy schema");
    const allowed = asArray(policy.allowedSpdx, "allowed SPDX licenses");
    if (
        !allowed.length ||
        !allowed.every(
            (item) => typeof item === "string" && item && item !== "NOASSERTION"
        ) ||
        new Set(allowed).size !== allowed.length
    )
        fail("Allowed SPDX licenses are invalid");
    exactKeys(
        policy.obligationEvidence,
        allowed,
        "base-license obligation evidence"
    );
    for (const expression of allowed) {
        const tree = parseSpdx(expression);
        if (hasOr(tree))
            fail("Base allowed licenses cannot contain OR expressions");
        validateObligationEvidence(
            policy.obligationEvidence[expression],
            `allowed license ${expression}`
        );
    }
    const reviewed = asArray(
        policy.reviewedExpressions,
        "reviewed license expressions"
    );
    const seen = new Set();
    for (const item of reviewed) {
        exactKeys(
            item,
            [
                "expression",
                "selected",
                "owner",
                "approver",
                "reviewReference",
                "obligationEvidence",
            ],
            "reviewed license expression"
        );
        if (seen.has(item.expression))
            fail("Duplicate reviewed license expression");
        seen.add(item.expression);
        const tree = parseSpdx(item.expression);
        let selectedTree;
        try {
            selectedTree = parseSpdx(item.selected);
        } catch {
            fail(
                `Reviewed expression ${item.expression} has malformed selection`
            );
        }
        const selectedCanonical = canonicalSpdx(selectedTree);
        const offered = offeredOrBranches(tree).map(canonicalSpdx);
        if (
            hasOr(selectedTree) ||
            !offered.includes(selectedCanonical) ||
            [...collectLicenseIds(selectedTree)].some(
                (id) => !allowed.includes(id)
            )
        )
            fail(
                `Reviewed expression ${item.expression} has an unavailable exact branch selection`
            );
        for (const field of ["owner", "approver", "reviewReference"])
            if (typeof item[field] !== "string" || !item[field])
                fail(`Reviewed expression ${item.expression} lacks ${field}`);
        validateObligationEvidence(
            item.obligationEvidence,
            `reviewed expression ${item.expression}`
        );
    }
    return policy;
}
function licenseAllowed(expression, policy) {
    const blocked = (selected = null, missingObligationReasons = []) => ({
        allowed: false,
        selected,
        obligationEvidence: null,
        missingObligationReasons,
    });
    if (expression === "NOASSERTION") return blocked();
    let tree;
    try {
        tree = parseSpdx(expression);
    } catch {
        return blocked();
    }
    const ids = [...collectLicenseIds(tree)];
    const isBaseExpression =
        !hasOr(tree) &&
        !hasException(tree) &&
        ids.every((id) => policy.allowedSpdx.includes(id));
    if (isBaseExpression) {
        const missing = ids
            .map((id) => policy.obligationEvidence[id])
            .filter((evidence) => evidence.obligationsComplete !== true)
            .map((evidence) => evidence.missingReason);
        if (missing.length) return blocked(expression, missing);
        return {
            allowed: true,
            selected: expression,
            obligationEvidence: ids.map((id) => ({
                path: policy.obligationEvidence[id].evidencePath,
                digest: policy.obligationEvidence[id].evidenceDigest,
            })),
            missingObligationReasons: [],
        };
    }
    const reviewed = policy.reviewedExpressions.find(
        (item) => item.expression === expression
    );
    if (!reviewed) return blocked();
    if (reviewed.obligationEvidence.obligationsComplete !== true)
        return blocked(reviewed.selected, [
            reviewed.obligationEvidence.missingReason,
        ]);
    return {
        allowed: true,
        selected: reviewed.selected,
        obligationEvidence: {
            path: reviewed.obligationEvidence.evidencePath,
            digest: reviewed.obligationEvidence.evidenceDigest,
        },
        missingObligationReasons: [],
    };
}

function npmPurl(component) {
    if (
        typeof component?.purl !== "string" ||
        !component.purl.startsWith("pkg:npm/")
    )
        return null;
    const value = component.purl.slice("pkg:npm/".length).split("?")[0];
    const split = value.lastIndexOf("@");
    if (split <= 0) return null;
    return {
        name: decodeURIComponent(value.slice(0, split)),
        version: decodeURIComponent(value.slice(split + 1)),
    };
}
function lockPackages() {
    const packages = new Map();
    for (const match of fs
        .readFileSync("yarn.lock", "utf8")
        .matchAll(/^\s*resolution:\s*"((?:@[^/"]+\/)?[^@"]+)@npm:([^"]+)"/gm))
        packages.set(`${match[1]}@${match[2]}`, {
            name: match[1],
            version: match[2],
        });
    if (!packages.size) fail("No registry packages found in yarn.lock");
    return [...packages.values()];
}

function npmPackageUrl(name, version) {
    const encodedName = name.startsWith("@")
        ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}`
        : encodeURIComponent(name);
    return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

function generateSourceSbom(licenseReportPath, outputPath) {
    const report = readJson(licenseReportPath);
    const subjectReport = validateSubject(report.subject);
    validateEnvelope(report, "license-inventory", subjectReport, Date.now());
    exactKeys(report.payload, ["components"], "license inventory payload");
    const inventory = asArray(report.payload.components, "license components");
    const expectedRegistry = new Set(
        lockPackages().map((item) => `${item.name}@${item.version}`)
    );
    const components = new Map();
    for (const [index, item] of inventory.entries()) {
        exactKeys(
            item,
            ["component", "locator", "version", "scope", "spdxExpression"],
            `license component ${index + 1}`
        );
        const key = `${item.component}@${item.version}`;
        if (item.scope === "resolved" && !expectedRegistry.has(key))
            fail(`License inventory has non-lockfile registry package ${key}`);
        if (!["resolved", "workspace"].includes(item.scope))
            fail(`License inventory component ${key} has invalid scope`);
        const prior = components.get(`${item.scope}:${key}`);
        if (prior && prior.licenses[0].expression !== item.spdxExpression)
            fail(`License inventory has conflicting expressions for ${key}`);
        const purl = npmPackageUrl(item.component, item.version);
        components.set(`${item.scope}:${key}`, {
            type: item.scope === "workspace" ? "application" : "library",
            name: item.component,
            version: item.version,
            purl,
            "bom-ref": purl,
            licenses: [{ expression: item.spdxExpression }],
        });
    }
    const actualRegistry = new Set(
        [...components.keys()]
            .filter((key) => key.startsWith("resolved:"))
            .map((key) => key.slice("resolved:".length))
    );
    if (
        actualRegistry.size !== expectedRegistry.size ||
        [...expectedRegistry].some((key) => !actualRegistry.has(key))
    )
        fail(
            "License inventory does not exactly cover every registry lock package"
        );
    const payload = sanitizeSourceSbom({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components: [...components.values()].sort((left, right) =>
            left.purl.localeCompare(right.purl)
        ),
    });
    writeJson(outputPath, payload);
}

function evaluate(directory) {
    const now = Date.now();
    const subjectReport = validateSubject(
        readJson(path.join(directory, "subject.json"))
    );
    if (
        subjectReport.commit !== git("rev-parse", "HEAD") ||
        subjectReport.lockDigest !== sha256File("yarn.lock")
    )
        fail("Subject is not the exact HEAD and lockfile");
    if (
        !["local", "pull_request", "push", "schedule"].includes(
            subjectReport.workflow.eventName
        ) ||
        subjectReport.workflow.ref.startsWith("refs/tags/")
    )
        fail("Untrusted workflow event or tag subject");
    const reports = Object.fromEntries(
        requiredTypes.map((type) => {
            const report = readJson(path.join(directory, `${type}.json`));
            validateEnvelope(report, type, subjectReport, now);
            return [type, report];
        })
    );
    validateSanitizedPayloads(reports);
    const dependencyDatabase = reports["dependency-vulnerabilities"].scanner;
    const imageDatabase = reports["image-vulnerabilities"].scanner;
    if (
        dependencyDatabase.databaseUpdatedAt !==
            imageDatabase.databaseUpdatedAt ||
        dependencyDatabase.databaseIdentity !== imageDatabase.databaseIdentity
    )
        fail(
            "Dependency and image scans did not use the exact same Grype database snapshot"
        );
    const sourceSbom = reports["source-sbom"];
    const imageSbom = reports["image-sbom"];
    if (
        sourceSbom.payload?.bomFormat !== "CycloneDX" ||
        !Array.isArray(sourceSbom.payload.components) ||
        !sourceSbom.payload.components.length
    )
        fail("Source SBOM is not a non-empty CycloneDX document");
    if (
        reports["dependency-vulnerabilities"].scanner.inputDigest !==
        sourceSbom.rawDigest
    )
        fail("Dependency scan did not consume the exact source SBOM");
    if (
        !String(imageSbom.payload?.spdxVersion || "").startsWith("SPDX-") ||
        !Array.isArray(imageSbom.payload.packages) ||
        !imageSbom.payload.packages.length
    )
        fail("Image SBOM is not a non-empty SPDX document");
    const imagePackageIds = imageSbom.payload.packages.map(
        (component) => component.SPDXID
    );
    if (new Set(imagePackageIds).size !== imagePackageIds.length)
        fail("Image SPDX document contains duplicate package IDs");
    const requiredImageComponents = new Map([
        ["node", "24.19.0"],
        ["@staticdeploy/staticdeploy", "0.15.5"],
    ]);
    for (const [name, version] of requiredImageComponents) {
        if (
            !imageSbom.payload.packages.some(
                (component) =>
                    component.name === name && component.versionInfo === version
            )
        )
            fail(`Image SPDX document omits ${name}@${version}`);
    }
    const imageHex = subjectReport.imageConfigDigest.slice("sha256:".length);
    const rootId = imageSbom.payload.documentDescribes[0];
    const imagePackage = imageSbom.payload.packages.find(
        (component) => component.SPDXID === rootId
    );
    if (
        !imagePackage ||
        imagePackage.versionInfo !== imageHex ||
        !String(imagePackage.SPDXID).startsWith(
            "SPDXRef-DocumentRoot-Image-"
        ) ||
        !(imagePackage.externalRefs || []).some(
            (reference) =>
                reference.referenceType === "purl" &&
                reference.referenceLocator.startsWith("pkg:oci/") &&
                reference.referenceLocator.includes(`tag=${imageHex}`)
        )
    )
        fail(
            "Image SPDX document root does not identify the exact local image config digest"
        );
    if (
        reports["image-vulnerabilities"].scanner.inputDigest !==
            subjectReport.imageConfigDigest ||
        reports["image-vulnerabilities"].payload?.target?.imageID !==
            subjectReport.imageConfigDigest
    )
        fail(
            "Image vulnerability scan did not identify the exact image config digest"
        );

    const secrets = sanitizeSecrets({
        schemaVersion: 1,
        scanner: "trufflehog",
        findings: reports.secrets.payload.findings,
    }).findings;
    if (secrets.some((item) => item.source.commit !== subjectReport.commit))
        fail("Secret scan finding does not identify the exact subject");
    const findings = [
        ...grypeFindings(
            reports["dependency-vulnerabilities"],
            "resolved-dependency"
        ),
        ...grypeFindings(reports["image-vulnerabilities"], "image"),
        ...sastFindings(reports.sast),
    ];
    const exceptionPolicy = readJson(
        process.env.VULNERABILITY_EXCEPTIONS_PATH ||
            "config/vulnerability-exceptions.json"
    );
    const exceptions = validateExceptions(exceptionPolicy, subjectReport, now);
    const evaluatedFindings = findings.map((finding) => {
        const exception = blockingSeverities.has(finding.severity)
            ? exactException(finding, subjectReport, exceptions)
            : undefined;
        return {
            ...finding,
            disposition: exception
                ? "excepted"
                : blockingSeverities.has(finding.severity)
                  ? "blocked"
                  : "advisory",
            exceptionId: exception?.id || null,
        };
    });
    const vulnerabilityPassed =
        evaluatedFindings.every((item) => item.disposition !== "blocked") &&
        secrets.length === 0;
    writeJson(path.join(directory, "normalized-findings.json"), {
        schemaVersion: SCHEMA_VERSION,
        subject: subjectReport,
        generatedAt: new Date(now).toISOString(),
        findings: evaluatedFindings,
        secretFindingCount: secrets.length,
    });
    writeJson(path.join(directory, "vulnerability-evaluation.json"), {
        schemaVersion: SCHEMA_VERSION,
        subject: subjectReport,
        evaluatedAt: new Date(now).toISOString(),
        passed: vulnerabilityPassed,
        blockingFindingCount: evaluatedFindings.filter(
            (item) => item.disposition === "blocked"
        ).length,
        advisoryFindingCount: evaluatedFindings.filter(
            (item) => item.disposition === "advisory"
        ).length,
        secretFindingCount: secrets.length,
    });

    const licensePolicy = validateLicensePolicy(
        readJson(
            process.env.LICENSE_POLICY_PATH || "config/license-policy.json"
        )
    );
    const dependencyComponents = asArray(
        reports["license-inventory"].payload?.components,
        "license components"
    );
    const inventoryByKey = new Map();
    for (const item of dependencyComponents) {
        const key = `${item.scope}:${item.component}@${item.version}`;
        const prior = inventoryByKey.get(key);
        if (prior && prior.spdxExpression !== item.spdxExpression)
            fail(`License inventory conflicts for ${key}`);
        inventoryByKey.set(key, item);
    }
    const expectedRegistry = new Set(
        lockPackages().map((item) => `resolved:${item.name}@${item.version}`)
    );
    for (const key of expectedRegistry)
        if (!inventoryByKey.has(key))
            fail(`License inventory omits lockfile package ${key}`);
    for (const key of inventoryByKey.keys())
        if (key.startsWith("resolved:") && !expectedRegistry.has(key))
            fail(`License inventory contains non-lockfile package ${key}`);
    const sourceByKey = new Map();
    for (const component of sourceSbom.payload.components) {
        const parsed = npmPurl(component);
        if (!parsed) fail("Source SBOM contains a non-npm component");
        const sourceScope =
            component.type === "application" ? "workspace" : "resolved";
        const key = `${sourceScope}:${parsed.name}@${parsed.version}`;
        const inventory = inventoryByKey.get(key);
        if (!inventory)
            fail(
                `Source SBOM contains component absent from license inventory: ${key}`
            );
        if (component.licenses[0].expression !== inventory.spdxExpression)
            fail(`Source SBOM license disagrees with inventory for ${key}`);
        if (sourceByKey.has(key))
            fail(`Source SBOM duplicates component ${key}`);
        sourceByKey.set(key, component);
    }
    if (
        sourceByKey.size !== inventoryByKey.size ||
        [...inventoryByKey.keys()].some((key) => !sourceByKey.has(key))
    )
        fail(
            "Source SBOM and exact lock/workspace license inventory are not bidirectionally complete"
        );
    const documentRootIds = new Set(imageSbom.payload.documentDescribes);
    const imageComponents = imageSbom.payload.packages
        .filter((component) => !documentRootIds.has(component.SPDXID))
        .map((component, index) => ({
            component: component.name || `unknown-image-component-${index}`,
            locator: component.SPDXID || `image-component-${index}`,
            version: component.versionInfo || "NOASSERTION",
            scope: "image",
            spdxExpression:
                component.licenseConcluded &&
                component.licenseConcluded !== "NOASSERTION"
                    ? component.licenseConcluded
                    : component.licenseDeclared || "NOASSERTION",
        }));
    const components = [...dependencyComponents, ...imageComponents];
    writeJson(path.join(directory, "normalized-license-inventory.json"), {
        schemaVersion: SCHEMA_VERSION,
        subject: subjectReport,
        generatedAt: new Date(now).toISOString(),
        components,
    });
    const licenseResults = components.map((component) => ({
        ...component,
        ...licenseAllowed(component.spdxExpression, licensePolicy),
    }));
    const licensePassed = licenseResults.every((item) => item.allowed);
    writeJson(path.join(directory, "license-evaluation.json"), {
        schemaVersion: SCHEMA_VERSION,
        subject: subjectReport,
        evaluatedAt: new Date(now).toISOString(),
        passed: licensePassed,
        prohibitedCount: licenseResults.filter((item) => !item.allowed).length,
        components: licenseResults,
    });
    if (!vulnerabilityPassed || !licensePassed)
        fail(
            `Security policy failed: vulnerabilities=${vulnerabilityPassed}, licenses=${licensePassed}`
        );
    console.log(
        `Security policy passed for ${subjectReport.commit} and ${subjectReport.imageConfigDigest}`
    );
}

const [command, ...args] = process.argv.slice(2);
if (command === "subject" && args.length === 2) subject(args[0], args[1]);
else if (command === "record" && args.length === 3)
    record(args[0], args[1], args[2]);
else if (command === "generate-source-sbom" && args.length === 2)
    generateSourceSbom(args[0], args[1]);
else if (command === "evaluate" && args.length === 1) evaluate(args[0]);
else
    fail(
        "usage: security-policy.mjs subject OUTPUT IMAGE_CONFIG_DIGEST | record TYPE RAW OUTPUT | generate-source-sbom LICENSE_REPORT OUTPUT | evaluate REPORT_DIRECTORY"
    );
