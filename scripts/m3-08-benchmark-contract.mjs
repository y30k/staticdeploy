const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function metric(samples) {
    if (
        !Array.isArray(samples) ||
        samples.length === 0 ||
        samples.some((value) => !Number.isFinite(value) || value < 0)
    )
        throw new Error("benchmark samples are invalid");
    const sorted = [...samples].sort((left, right) => left - right);
    const percentile = (fraction) =>
        sorted[
            Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)
        ];
    return {
        iterations: sorted.length,
        minMs: Number(sorted[0].toFixed(3)),
        p50Ms: Number(percentile(0.5).toFixed(3)),
        p95Ms: Number(percentile(0.95).toFixed(3)),
        maxMs: Number(sorted.at(-1).toFixed(3)),
        meanMs: Number(
            (
                sorted.reduce((total, value) => total + value, 0) /
                sorted.length
            ).toFixed(3)
        ),
    };
}

export function assertClaimRows(rows, expected) {
    if (!Array.isArray(rows) || rows.length !== expected.count)
        throw new Error(
            `claim returned ${rows?.length ?? "invalid"} rows; expected ${expected.count}`
        );
    const ids = new Set();
    for (const row of rows) {
        if (!UUID.test(row.id) || ids.has(row.id))
            throw new Error("claim returned an invalid or duplicate id");
        ids.add(row.id);
        if (row.lease_owner !== expected.owner)
            throw new Error("claim returned the wrong lease owner");
        const identity = expected.identityFor(row);
        if (
            Number(row.attempt_count) !== identity.attemptCount ||
            Number(row.lease_version) !== identity.leaseVersion
        )
            throw new Error(
                "claim returned the wrong attempt or lease version"
            );
        if (row.state !== "LEASED" || row.next_attempt_at !== null)
            throw new Error("claim returned an invalid lifecycle state");
    }
    return ids;
}

export function assertConcurrentClaims(claims, expectedPerClaim) {
    if (!Array.isArray(claims) || claims.length === 0)
        throw new Error("concurrent claim results are missing");
    const all = new Set();
    for (const { owner, rows } of claims) {
        const ids = assertClaimRows(rows, {
            count: expectedPerClaim,
            owner,
            identityFor: () => ({ attemptCount: 1, leaseVersion: 1 }),
        });
        for (const id of ids) {
            if (all.has(id))
                throw new Error("concurrent claims returned overlapping ids");
            all.add(id);
        }
    }
    if (all.size !== claims.length * expectedPerClaim)
        throw new Error(
            "concurrent claims did not return the complete disjoint set"
        );
    return all;
}

export function assertObjectRefresh(result) {
    if (result?.source !== "OBJECT")
        throw new Error("content refresh did not use verified object storage");
    return result;
}

export function assertReconciliationRow(row, expectedApplicationId) {
    if (
        row?.id !== expectedApplicationId ||
        Number(row.desired_generation) !== 2 ||
        Number(row.served_generation) !== 0 ||
        row.outbox_id !== null ||
        row.superseded_count !== "1"
    )
        throw new Error(
            "reconciliation fixture did not exercise the exact superseded-count contract"
        );
    return row;
}

export async function runCleanupSteps(steps) {
    const errors = [];
    for (const { label, operation } of steps) {
        try {
            await operation();
        } catch (error) {
            errors.push(
                new Error(
                    `${label}: ${error instanceof Error ? error.message : String(error)}`
                )
            );
        }
    }
    return errors;
}

export function assertRequiredPlans(plans) {
    const required = {
        keyRetirable: ["v2_outbox_routing_kid_active_idx"],
        reconciliation: [
            "v2_publication_outbox_application_generation_unique",
            "v2_publication_outbox_application_generation_idx",
        ],
    };
    for (const [name, indexes] of Object.entries(required)) {
        if (!indexes.some((index) => plans?.[name]?.indexes?.includes(index)))
            throw new Error(
                `${name} plan does not use any required index: ${indexes.join(", ")}`
            );
    }
}
