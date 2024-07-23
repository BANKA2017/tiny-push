BEGIN TRANSACTION;
DROP TABLE IF EXISTS "channel";
CREATE TABLE IF NOT EXISTS "channel" (
	"uuid"	TEXT NOT NULL UNIQUE,
	"endpoint"	TEXT NOT NULL,
	"auth"	TEXT NOT NULL,
	"p256dh"	TEXT NOT NULL,
	"target"	TEXT NOT NULL DEFAULT 'webpush',
	"last_used"	INTEGER NOT NULL DEFAULT 0,
	"count"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("uuid")
);
DROP INDEX IF EXISTS "idx_channel_uuid";
CREATE UNIQUE INDEX IF NOT EXISTS "idx_channel_uuid" ON "channel" (
	"uuid"
);
DROP INDEX IF EXISTS "idx_channel_latest_used";
CREATE INDEX "idx_channel_latest_used" ON "channel" (
	"last_used"	ASC
);
COMMIT;
