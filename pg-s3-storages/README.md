# @staticdeploy/pg-s3-storages

Gateway for storage resources backed by [S3](https://aws.amazon.com/s3/) (or any
API compatible alternative like [MinIO](https://min.io/)) to store static files,
and [PostgreSQL](https://www.postgresql.org/) to store metadata about the files,
as well as the other entities of StaticDeploy.

The S3 client accepts an explicit endpoint and region, with path-style
addressing enabled by default for backward-compatible MinIO behavior. Set both
`accessKeyId` and `secretAccessKey` for explicit credentials, or omit both to
use the AWS SDK default Node credential provider chain. `enableGCSCompatibility`
continues to replace bulk deletes with individual object deletes for GCS.
