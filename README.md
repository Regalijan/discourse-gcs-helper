# Discourse GCS Helper

This plugin fixes various methods of Discourse which don't work properly with Google Cloud Storage.

Particularly:
- Lifecycle rules
- Moving objects to tombstone
- Expiring old assets

To use this plugin, install it as you would any other Discourse plugin.
But before you rebuild, you need to download a key file of a service account, and place that in
`/var/discourse/shared/standalone/gcs.json`, or elsewhere the Docker container can see it provided
you set the path of the file in the `STORAGE_CREDENTIALS_PATH` environment variable.
