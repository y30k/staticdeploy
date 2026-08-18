import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const SCHEMA_VERSION = 1;
const MAX_REPORT_AGE_MS = 2 * 60 * 60 * 1000;
const MAX_DATABASE_AGE_MS = 24 * 60 * 60 * 1000;
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

const fail = (message) => {
    throw new Error(message);
};
const readJson = (file) => {
    const text = fs.readFileSync(file, "utf8");
    if (!text.trim()) fail(`Required report is empty: ${file}`);
    try {
        return JSON.parse(text);
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
const iso = (value, field) => {
    const time = Date.parse(value);
    if (!Number.isFinite(time)) fail(`${field} must be an ISO timestamp`);
    return time;
};
const asArray = (value, field) => {
    if (!Array.isArray(value)) fail(`${field} must be an array`);
    return value;
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

function subject(output, imageDigest = null) {
    const commit = process.env.SECURITY_COMMIT || git("rev-parse", "HEAD");
    if (!/^[a-f0-9]{40}$/.test(commit))
        fail("Subject commit must be a full SHA");
    if (imageDigest !== null && !/^sha256:[a-f0-9]{64}$/.test(imageDigest))
        fail("Image digest must be sha256:<64 lowercase hex>");
    writeJson(output, {
        schemaVersion: SCHEMA_VERSION,
        commit,
        lockDigest: sha256File("yarn.lock"),
        imageDigest,
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
    return records.map((record, index) => {
        const locator = record?.value;
        const version = record?.children?.Version;
        const license = record?.children?.Manifest?.License;
        if (typeof locator !== "string" || typeof version !== "string")
            fail(`License record ${index + 1} lacks component/version`);
        return {
            component: locator.replace(/@(?:npm|workspace):.*$/, ""),
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

function record(type, rawPath, outputPath) {
    if (!requiredTypes.includes(type)) fail(`Unknown report type: ${type}`);
    const subjectReport = readJson(
        process.env.SECURITY_SUBJECT ||
            path.join(path.dirname(outputPath), "subject.json")
    );
    const raw = fs.readFileSync(rawPath, "utf8");
    if (!raw.trim() && type !== "dependency-vulnerabilities")
        fail(`Scanner output is empty: ${rawPath}`);
    let payload;
    if (type === "dependency-vulnerabilities" || type === "license-inventory") {
        const records = raw.trim() ? parseNdjson(raw, rawPath) : [];
        payload =
            type === "license-inventory"
                ? { components: normalizeLicenseRecords(records) }
                : { advisories: records };
    } else {
        payload = readJson(rawPath);
    }
    const startedAt = process.env.SCANNER_STARTED_AT;
    const completedAt = process.env.SCANNER_COMPLETED_AT;
    iso(startedAt, "SCANNER_STARTED_AT");
    iso(completedAt, "SCANNER_COMPLETED_AT");
    const exitCode = Number(process.env.SCANNER_EXIT_CODE);
    if (!Number.isInteger(exitCode))
        fail("SCANNER_EXIT_CODE must be an integer");
    const acceptedExitCodes = (process.env.SCANNER_ACCEPTED_EXIT_CODES || "0")
        .split(",")
        .map(Number);
    writeJson(outputPath, {
        schemaVersion: SCHEMA_VERSION,
        type,
        subject: subjectReport,
        scanner: {
            name: process.env.SCANNER_NAME,
            version: process.env.SCANNER_VERSION,
            identity: process.env.SCANNER_IDENTITY,
            rulesetDigest: process.env.SCANNER_RULESET_DIGEST || null,
            databaseUpdatedAt: process.env.SCANNER_DATABASE_UPDATED_AT || null,
        },
        startedAt,
        completedAt,
        exitCode,
        acceptedExitCodes,
        complete:
            process.env.SCANNER_COMPLETE === "true" &&
            acceptedExitCodes.includes(exitCode),
        rawDigest: sha256File(rawPath),
        payload,
    });
}

function validateEnvelope(report, expectedType, subjectReport, now) {
    if (report.schemaVersion !== SCHEMA_VERSION || report.type !== expectedType)
        fail(`${expectedType} has an unsupported schema/type`);
    if (
        report.subject?.commit !== subjectReport.commit ||
        report.subject?.lockDigest !== subjectReport.lockDigest ||
        report.subject?.workflow?.runId !== subjectReport.workflow.runId
    )
        fail(
            `${expectedType} identifies the wrong commit, lockfile, or workflow`
        );
    if (
        ["image-vulnerabilities", "image-sbom"].includes(expectedType) &&
        report.subject?.imageDigest !== subjectReport.imageDigest
    )
        fail(`${expectedType} identifies the wrong image digest`);
    const started = iso(report.startedAt, `${expectedType}.startedAt`);
    const completed = iso(report.completedAt, `${expectedType}.completedAt`);
    if (
        completed < started ||
        now - completed > MAX_REPORT_AGE_MS ||
        completed > now + 60_000
    )
        fail(`${expectedType} is stale or has invalid timestamps`);
    if (
        !report.complete ||
        !report.acceptedExitCodes?.includes(report.exitCode)
    )
        fail(`${expectedType} scanner failed or produced incomplete output`);
    for (const field of ["name", "version", "identity"]) {
        if (
            typeof report.scanner?.[field] !== "string" ||
            !report.scanner[field]
        )
            fail(`${expectedType} lacks scanner ${field}`);
    }
    if (expectedType === "sast" && !report.scanner.rulesetDigest)
        fail("SAST report lacks an immutable ruleset digest");
    if (
        ["dependency-vulnerabilities", "image-vulnerabilities"].includes(
            expectedType
        )
    ) {
        const updated = iso(
            report.scanner.databaseUpdatedAt,
            `${expectedType}.scanner.databaseUpdatedAt`
        );
        if (updated > completed || completed - updated > MAX_DATABASE_AGE_MS)
            fail(
                `${expectedType} vulnerability database is stale or future-dated`
            );
    }
}

function normalizeSeverity(value) {
    const severity = String(value || "unknown").toLowerCase();
    if (severity === "moderate") return "medium";
    if (severity === "negligible") return "low";
    return ["critical", "high", "medium", "low"].includes(severity)
        ? severity
        : "unknown";
}

function dependencyFindings(report) {
    return asArray(report.payload?.advisories, "dependency advisories").map(
        (advisory, index) => ({
            source: "yarn-audit",
            id: String(advisory?.children?.ID ?? `unknown-${index}`),
            aliases: [],
            component: advisory?.value || "unknown",
            version:
                (advisory?.children?.["Tree Versions"] || []).join(",") ||
                "unknown",
            path:
                (advisory?.children?.Dependents || []).join(" -> ") ||
                "unknown",
            severity: normalizeSeverity(advisory?.children?.Severity),
            scope: "resolved-dependency",
        })
    );
}
function imageFindings(report, imageDigest) {
    const payload = report.payload;
    if (payload?.source?.target?.imageID !== imageDigest)
        fail("Image vulnerability payload identifies the wrong image");
    return asArray(payload.matches, "image vulnerability matches").map(
        (match, index) => ({
            source: "grype",
            id: String(match?.vulnerability?.id || `unknown-${index}`),
            aliases:
                match?.vulnerability?.relatedVulnerabilities?.map(
                    (item) => item.id
                ) || [],
            component: match?.artifact?.name || "unknown",
            version: match?.artifact?.version || "unknown",
            path:
                (match?.artifact?.locations || [])
                    .map((item) => item.path)
                    .join(",") || "image",
            severity: normalizeSeverity(match?.vulnerability?.severity),
            scope: "image",
        })
    );
}
function sastFindings(report) {
    return asArray(report.payload?.results, "Semgrep results").map(
        (result, index) => ({
            source: "semgrep",
            id: result.check_id || `unknown-${index}`,
            aliases: [],
            component: result.path || "unknown",
            version: "source",
            path: `${result.path || "unknown"}:${result.start?.line || 0}`,
            severity:
                result.extra?.severity === "ERROR"
                    ? "high"
                    : result.extra?.severity === "WARNING"
                      ? "medium"
                      : result.extra?.severity === "INFO"
                        ? "low"
                        : "unknown",
            scope: "source",
        })
    );
}

function exactException(finding, subjectReport, exceptions, now) {
    return exceptions.find((item) => {
        if (
            !item ||
            item.findingId !== finding.id ||
            !Array.isArray(item.aliases) ||
            JSON.stringify([...item.aliases].sort()) !==
                JSON.stringify([...finding.aliases].sort()) ||
            item.component !== finding.component ||
            item.version !== finding.version ||
            item.path !== finding.path ||
            item.scope !== finding.scope ||
            item.severity !== finding.severity ||
            item.subjectCommit !== subjectReport.commit ||
            /[*?]/.test(JSON.stringify(item)) ||
            !item.owner ||
            !item.securityApprover ||
            (item.severity === "critical" && !item.releaseOwnerApprover) ||
            !item.reviewReference ||
            !item.remediationTracker ||
            !item.riskRationale ||
            !item.compensatingControls
        )
            return false;
        const created = Date.parse(item.createdAt);
        const expiry = Date.parse(item.expiresAt);
        const max = item.severity === "critical" ? 7 : 30;
        return (
            Number.isFinite(created) &&
            Number.isFinite(expiry) &&
            created <= now &&
            expiry > now &&
            expiry - created <= max * 24 * 60 * 60 * 1000
        );
    });
}

function licenseAllowed(expression, policy) {
    if (policy.allowedSpdx.includes(expression))
        return { allowed: true, selected: expression };
    if (
        !expression.includes(" OR ") &&
        !expression.includes(" WITH ") &&
        expression
            .split(/\s+AND\s+/)
            .map((item) => item.replace(/[()]/g, "").trim())
            .every((item) => item && policy.allowedSpdx.includes(item))
    )
        return { allowed: true, selected: expression };
    const reviewed = policy.reviewedExpressions.find(
        (item) => item.expression === expression
    );
    if (
        !reviewed ||
        !reviewed.owner ||
        !reviewed.approver ||
        !reviewed.reviewReference
    )
        return { allowed: false, selected: null };
    if (
        expression.includes(" OR ") &&
        !policy.allowedSpdx.includes(reviewed.selected)
    )
        return { allowed: false, selected: reviewed.selected || null };
    return {
        allowed: reviewed.obligationsComplete === true,
        selected: reviewed.selected || expression,
    };
}

function evaluate(directory) {
    const now = Date.now();
    const subjectReport = readJson(path.join(directory, "subject.json"));
    if (subjectReport.schemaVersion !== SCHEMA_VERSION)
        fail("Invalid subject schema");
    if (subjectReport.commit !== git("rev-parse", "HEAD"))
        fail("Subject commit is not HEAD");
    if (subjectReport.lockDigest !== sha256File("yarn.lock"))
        fail("Subject lock digest is stale");
    if (
        !["local", "pull_request", "push", "schedule"].includes(
            subjectReport.workflow?.eventName
        ) ||
        String(subjectReport.workflow?.ref || "").startsWith("refs/tags/")
    )
        fail("Untrusted workflow event or tag subject");
    if (!/^sha256:[a-f0-9]{64}$/.test(subjectReport.imageDigest || ""))
        fail("Subject lacks an immutable image digest");
    const reports = Object.fromEntries(
        requiredTypes.map((type) => {
            const report = readJson(path.join(directory, `${type}.json`));
            validateEnvelope(report, type, subjectReport, now);
            return [type, report];
        })
    );
    if (
        reports["source-sbom"].payload?.bomFormat !== "CycloneDX" ||
        !reports["source-sbom"].payload?.components?.length
    )
        fail("Source SBOM is not a non-empty CycloneDX document");
    if (
        !String(reports["image-sbom"].payload?.spdxVersion || "").startsWith(
            "SPDX-"
        ) ||
        !reports["image-sbom"].payload?.packages?.length
    )
        fail("Image SBOM is not a non-empty SPDX document");
    const secrets = asArray(
        reports.secrets.payload?.findings,
        "secret findings"
    );
    const findings = [
        ...dependencyFindings(reports["dependency-vulnerabilities"]),
        ...imageFindings(
            reports["image-vulnerabilities"],
            subjectReport.imageDigest
        ),
        ...sastFindings(reports.sast),
    ];
    const exceptionPolicy = readJson(
        process.env.VULNERABILITY_EXCEPTIONS_PATH ||
            "config/vulnerability-exceptions.json"
    );
    const exceptions = asArray(
        exceptionPolicy.exceptions,
        "vulnerability exceptions"
    );
    const evaluatedFindings = findings.map((finding) => {
        const exception = blockingSeverities.has(finding.severity)
            ? exactException(finding, subjectReport, exceptions, now)
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
    const verifiedSecrets = secrets.filter(
        (item) => item.status === "verified" || item.status === "unknown"
    );
    const vulnerabilityPassed =
        evaluatedFindings.every((item) => item.disposition !== "blocked") &&
        verifiedSecrets.length === 0;
    writeJson(path.join(directory, "normalized-findings.json"), {
        schemaVersion: SCHEMA_VERSION,
        subject: subjectReport,
        generatedAt: new Date(now).toISOString(),
        findings: evaluatedFindings,
        secretFindingCount: verifiedSecrets.length,
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
        secretFindingCount: verifiedSecrets.length,
    });
    const licensePolicy = readJson(
        process.env.LICENSE_POLICY_PATH || "config/license-policy.json"
    );
    const dependencyComponents = asArray(
        reports["license-inventory"].payload?.components,
        "license components"
    );
    const imageComponents = asArray(
        reports["image-sbom"].payload?.packages,
        "image SPDX packages"
    ).map((component, index) => ({
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
        `Security policy passed for ${subjectReport.commit} and ${subjectReport.imageDigest}`
    );
}

const [command, ...args] = process.argv.slice(2);
if (command === "subject" && (args.length === 1 || args.length === 2))
    subject(args[0], args[1]);
else if (command === "record" && args.length === 3)
    record(args[0], args[1], args[2]);
else if (command === "evaluate" && args.length === 1) evaluate(args[0]);
else
    fail(
        "usage: security-policy.mjs subject OUTPUT [IMAGE_DIGEST] | record TYPE RAW OUTPUT | evaluate REPORT_DIRECTORY"
    );
