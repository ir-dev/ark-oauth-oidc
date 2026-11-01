-- Rollback for 00004.
--
-- DROP COLUMN needs SQLite 3.35 (2021) or newer; on anything older the statement fails and the
-- column is simply left in place, which costs nothing because no earlier build reads it.
-- Rolling back re-enables every account that was deactivated, since the flag is what held them.

ALTER TABLE "users" DROP COLUMN "is_active";
