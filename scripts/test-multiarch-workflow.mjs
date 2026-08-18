#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const workflowPath = ".github/workflows/scans-and-images.yml";
const validate = (workflow) => {
    assert.match(workflow, /^permissions:\n\s+contents: read$/m);
    assert.doesNotMatch(workflow, /^\s+(?:packages|id-token):\s*write$/m);
    assert.match(
        workflow,
        /docker\/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8/
    );
    assert.match(
        workflow,
        /tonistiigi\/binfmt:qemu-v10\.2\.1@sha256:d3b963f787999e6c0219a48dba02978769286ff61a5f4d26245cb6a6e5567ea3/
    );
    assert.match(
        workflow,
        /docker\/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c/
    );
    for (const platform of ["linux/amd64", "linux/arm64"]) {
        assert.ok(
            workflow.includes(`--platform ${platform}`),
            `workflow must build ${platform}`
        );
        const architecture = platform.slice("linux/".length);
        assert.match(
            workflow,
            new RegExp(
                `test-image-conformance\\.mjs[\\s\\S]{0,120}staticdeploy-service:${architecture} ${platform}[\\s\\S]{0,120}image-conformance-${architecture}\\.json`
            ),
            `workflow must smoke ${platform} and retain conformance evidence`
        );
    }
    assert.equal(
        (workflow.match(/docker buildx build/g) || []).length,
        2,
        "workflow must perform two explicit single-platform builds"
    );
    assert.equal(
        (workflow.match(/\s--load\s/g) || []).length,
        2,
        "both platform builds must load only into the local daemon"
    );
    assert.match(workflow, /org\.opencontainers\.image\.revision=\$commit/);
    assert.equal(
        (
            workflow.match(
                /--metadata-file\s+reports\/build-(?:amd64|arm64)-metadata\.raw\.json/g
            ) || []
        ).length,
        2,
        "both builds must retain local OCI manifest metadata"
    );
    assert.equal(
        (
            workflow.match(
                /--output\s+type=oci,dest=reports\/image-(?:amd64|arm64)\.oci\.raw\.tar/g
            ) || []
        ).length,
        2,
        "both builds must produce local OCI manifests without registry output"
    );
    const dockerCommands = [
        ...workflow.matchAll(/^\s*docker\s+([^\n]+)/gm),
    ].map((match) => `docker ${match[1]}`);
    assert.ok(dockerCommands.length >= 6);
    for (const command of dockerCommands) {
        assert.match(
            command,
            /^docker (?:run\b|image inspect\b|buildx build\b)/,
            `unapproved Docker workflow command: ${command}`
        );
        assert.doesNotMatch(
            command,
            /;|&&|\|\|/,
            `Docker workflow commands cannot chain shell commands: ${command}`
        );
    }
    const approvedDockerRunImages = [
        "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
        "returntocorp/semgrep@sha256:a265d09a9ca712e6624aca09056304ce4314a695b7028d65c041dd53fd44c700",
        "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
        "anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253",
    ];
    const lines = workflow.split("\n");
    const dockerRuns = [];
    for (let index = 0; index < lines.length; index += 1) {
        if (!lines[index].trim().startsWith("docker run ")) continue;
        let command = lines[index].trim();
        while (command.endsWith("\\")) {
            index += 1;
            command = `${command.slice(0, -1)} ${lines[index].trim()}`;
        }
        dockerRuns.push(command);
    }
    assert.ok(dockerRuns.length >= 8);
    const optionsWithValues = new Set([
        "--env",
        "-e",
        "--volume",
        "-v",
        "--name",
        "--network",
        "--platform",
    ]);
    for (const command of dockerRuns) {
        assert.doesNotMatch(
            command,
            /;|&&|\|\|/,
            `Docker run commands cannot chain shell commands: ${command}`
        );
        const tokens = command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g);
        let index = 2;
        while (tokens[index]?.startsWith("-")) {
            const option = tokens[index];
            index +=
                optionsWithValues.has(option) && !option.includes("=") ? 2 : 1;
        }
        assert.ok(
            approvedDockerRunImages.includes(tokens[index]),
            `unapproved Docker run image: ${tokens[index] || command}`
        );
    }
    assert.doesNotMatch(workflow, /^\s*run:\s*docker\s/m);
    const actions = [...workflow.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map(
        (match) => match[1]
    );
    const approvedActions = [
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
    ];
    assert.ok(actions.length >= approvedActions.length);
    for (const action of actions)
        assert.ok(
            approvedActions.includes(action),
            `unapproved workflow action: ${action}`
        );
    assert.match(workflow, /write-multiarch-image-evidence\.mjs/);
    assert.match(workflow, /compare-multiarch-image-inventory\.mjs/);
    assert.match(workflow, /multiarch-images\.json/);
    assert.match(workflow, /multiarch-inventory\.json/);
    assert.doesNotMatch(
        workflow,
        /docker\s+(?:image\s+)?(?:login|push)|docker\s+buildx\s+imagetools\s+create|docker\/(?:login|build-push)-action|--push(?:=[^\s\\]+)?|type=registry|(?:^|[,\s])push=[^,\s]+|push:\s*true|skopeo\s+(?:copy|sync)|oras\s+(?:push|copy)|crane\s+(?:push|copy)|regctl\s+(?:image\s+copy|manifest\s+put)|(?:npm|yarn\s+npm)\s+publish|ghcr\.io|docker\.io\//im,
        "pull-request image workflow must contain no publication primitive"
    );
};

const workflow = fs.readFileSync(workflowPath, "utf8");
validate(workflow);
for (const publicationCommand of [
    "docker push registry.example/app",
    "docker image push registry.example/app",
    "docker buildx imagetools create registry.example/app",
    "docker buildx build --push=true .",
    "docker buildx build --output type=image,name=registry.example/app,push=true .",
    "skopeo copy docker://source docker://destination",
    "skopeo sync source destination",
    "oras push registry.example/artifact file",
    "oras copy source destination",
    "crane copy source destination",
    "regctl manifest put registry.example/app",
    "npm publish",
    "yarn npm publish",
])
    assert.throws(() => validate(`${workflow}\nrun: ${publicationCommand}\n`));
assert.throws(() =>
    validate(workflow.replace("    contents: read", "    packages: write"))
);
assert.throws(() =>
    validate(
        workflow.replace(
            "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
            "evil.example/image trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33"
        )
    )
);
assert.throws(() => validate(workflow.replace("--load \\", "--push \\")));
assert.throws(() =>
    validate(
        workflow.replace(
            "docker buildx build \\",
            "docker buildx build \\\n                    --push=1 \\"
        )
    )
);
assert.throws(() =>
    validate(
        workflow.replace(
            "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
            "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33 ; docker run --rm evil.example/image"
        )
    )
);
console.log(
    "Multi-architecture workflow is pinned, local-only, and fail-closed."
);
