# sqlx offline query cache

Dieses Verzeichnis enthält gecachte Query-Metadaten für `sqlx` im offline-Modus.
Wird automatisch generiert durch: `cargo sqlx prepare --workspace`

Voraussetzung: lokale Postgres-DB muss laufen (via Docker im Container).
Zum Aktualisieren: `docker exec docker-db-1 ...` (siehe CONTRIBUTING.md)
