import {
    DeleteObjectCommand,
    DeleteObjectsCommand,
    GetObjectCommand,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import {
    IAssetWithContent,
    IBaseBundle,
    IBundlesStorage,
    IBundleWithoutAssetsContent,
} from "@staticdeploy/core";
import { Knex } from "knex";
import { flatMap, map, omit } from "lodash";
import { join } from "path";

import concurrentForEach from "./common/concurrentForEach";
import convertErrors from "./common/convertErrors";
import { isS3NotFoundError } from "./common/s3Errors";
import tables from "./common/tables";

@convertErrors
export default class BundlesStorage implements IBundlesStorage {
    constructor(
        private knex: Knex,
        private s3Client: S3Client,
        private s3Bucket: string,
        private s3EnableGCSCompatibility: boolean
    ) {}

    async findOne(id: string): Promise<IBundleWithoutAssetsContent | null> {
        const [bundle = null] = await this.knex(tables.bundles).where({ id });
        return bundle;
    }

    async findLatestByNameAndTag(
        name: string,
        tag: string
    ): Promise<IBundleWithoutAssetsContent | null> {
        const [bundle = null] = await this.knex(tables.bundles)
            .where({ name, tag })
            .orderBy("createdAt", "desc")
            .limit(1);
        return bundle;
    }

    async getBundleAssetContent(
        bundleId: string,
        assetPath: string
    ): Promise<Buffer | null> {
        const assetS3Key = this.getAssetS3Key(bundleId, assetPath);
        try {
            const s3Object = await this.s3Client.send(
                new GetObjectCommand({
                    Bucket: this.s3Bucket,
                    Key: assetS3Key,
                })
            );
            if (s3Object.Body === undefined) {
                throw new Error(`S3 object ${assetS3Key} has no body`);
            }
            return Buffer.from(await s3Object.Body.transformToByteArray());
        } catch (err) {
            // Preserve the storage contract: an S3 HTTP 404 is absence; other
            // SDK/service/provider errors remain failures for conversion by
            // the storage error decorator.
            if (isS3NotFoundError(err)) {
                return null;
            }
            throw err;
        }
    }

    async findMany(): Promise<IBaseBundle[]> {
        const bundles = await this.knex(tables.bundles).select(
            "id",
            "name",
            "tag",
            "createdAt"
        );
        return bundles;
    }

    async findManyByNameAndTag(
        name: string,
        tag: string
    ): Promise<IBundleWithoutAssetsContent[]> {
        const bundles = await this.knex(tables.bundles).where({ name, tag });
        return bundles;
    }

    async findManyNames(): Promise<string[]> {
        const results = await this.knex(tables.bundles).distinct("name");
        return map(results, "name");
    }

    async findManyTagsByName(name: string): Promise<string[]> {
        const results = await this.knex(tables.bundles)
            .where({ name })
            .distinct("tag");
        return map(results, "tag");
    }

    async oneExistsWithId(id: string): Promise<boolean> {
        const [app = null] = await this.knex(tables.bundles)
            .select("id")
            .where({ id });
        return app !== null;
    }

    async createOne(toBeCreatedBundle: {
        id: string;
        name: string;
        tag: string;
        description: string;
        hash: string;
        assets: IAssetWithContent[];
        fallbackAssetPath: string;
        fallbackStatusCode: number;
        createdAt: Date;
    }): Promise<IBundleWithoutAssetsContent> {
        // Upload files to S3
        await concurrentForEach(toBeCreatedBundle.assets, async (asset) => {
            await this.s3Client.send(
                new PutObjectCommand({
                    Bucket: this.s3Bucket,
                    Body: asset.content,
                    Key: this.getAssetS3Key(toBeCreatedBundle.id, asset.path),
                })
            );
        });
        // Omit the assets' content before saving the bundle to sql
        const bundleWithoutAssetsContent = {
            ...toBeCreatedBundle,
            assets: JSON.stringify(
                toBeCreatedBundle.assets.map((asset) => omit(asset, "content"))
            ),
        };
        const [createdBundle] = await this.knex(tables.bundles)
            .insert(bundleWithoutAssetsContent)
            .returning("*");
        return createdBundle;
    }

    async deleteMany(ids: string[]): Promise<void> {
        const bundles: IBundleWithoutAssetsContent[] = await this.knex(
            tables.bundles
        ).whereIn("id", ids);
        // Delete bundles' files on S3
        await this.deleteBundlesFiles(bundles);
        // Delete the bundles from sql
        await this.knex(tables.bundles).whereIn("id", ids).delete();
    }

    private async deleteBundlesFiles(bundles: IBundleWithoutAssetsContent[]) {
        const s3Keys = flatMap(bundles, (bundle) =>
            map(bundle.assets, (asset) =>
                this.getAssetS3Key(bundle.id, asset.path)
            )
        );
        if (this.s3EnableGCSCompatibility) {
            await this.deleteObjectsIndividually(s3Keys);
        } else {
            await this.deleteObjectsInBulk(s3Keys);
        }
    }

    private async deleteObjectsIndividually(s3Keys: string[]) {
        await concurrentForEach(s3Keys, async (s3Key) =>
            this.s3Client.send(
                new DeleteObjectCommand({
                    Bucket: this.s3Bucket,
                    Key: s3Key,
                })
            )
        );
    }

    private async deleteObjectsInBulk(s3Keys: string[]) {
        // S3 accepts at most 1,000 objects per DeleteObjects request. Process
        // batches sequentially so a failed batch leaves SQL metadata intact and
        // a retry can safely repeat already completed object deletions.
        for (let index = 0; index < s3Keys.length; index += 1000) {
            const response = await this.s3Client.send(
                new DeleteObjectsCommand({
                    Bucket: this.s3Bucket,
                    Delete: {
                        Objects: map(
                            s3Keys.slice(index, index + 1000),
                            (s3Key) => ({ Key: s3Key })
                        ),
                    },
                })
            );
            const errorCount = response.Errors?.length ?? 0;
            if (errorCount > 0) {
                throw new Error(
                    `S3 bulk delete failed for ${errorCount} object(s)`
                );
            }
        }
    }

    private getAssetS3Key(bundleId: string, assetPath: string) {
        // When using minio.io as an S3 server, keys can't have a leading /
        // (unlike in AWS S3), so we omit it
        return join(bundleId, assetPath);
    }
}
