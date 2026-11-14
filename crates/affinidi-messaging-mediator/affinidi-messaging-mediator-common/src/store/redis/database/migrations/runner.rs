/*!
 * Migration runner — checks which migrations have been applied and runs pending ones.
 *
 * Handles bootstrapping from the legacy GLOBAL:SCHEMA_VERSION system:
 * - If SCHEMA_MIGRATIONS set doesn't exist but GLOBAL:SCHEMA_VERSION does,
 *   seeds the migration set based on the legacy version.
 * - After bootstrap, removes the legacy SCHEMA_VERSION field.
 */

use super::{MigrationDef, all_migrations};
use crate::error_codes;
use crate::errors::MediatorError;
use crate::store::redis::database::Database;
use crate::store::redis::init::RedisInitConfig;
use semver::Version;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

const MIGRATIONS_SET_KEY: &str = "SCHEMA_MIGRATIONS";

/// Held by the instance running migrations, so instances starting together
/// do not run them concurrently. Expires on its own if its holder dies.
const MIGRATION_LOCK_KEY: &str = "SCHEMA_MIGRATIONS:LOCK";

/// How long the migration lock is held at most.
const MIGRATION_LOCK_TTL: Duration = Duration::from_secs(300);

/// How long an instance waits for another's migrations before giving up.
const MIGRATION_LOCK_WAIT: Duration = Duration::from_secs(600);

/// Release the lock KEYS[1] only if ARGV[1] still holds it.
static RELEASE_LOCK: std::sync::LazyLock<redis::Script> = std::sync::LazyLock::new(|| {
    redis::Script::new(
        r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#,
    )
});

/// Run all pending migrations in order, holding [`MIGRATION_LOCK_KEY`].
/// Called during mediator startup from database initialization.
///
/// Refuses to start when the database records a migration this build does
/// not know: a newer mediator has migrated the schema, and this one would
/// run against data it was not written for.
pub(crate) async fn run_pending_migrations(
    db: &Database,
    config: &RedisInitConfig,
) -> Result<(), MediatorError> {
    let token = uuid::Uuid::new_v4().to_string();
    let deadline = std::time::Instant::now() + MIGRATION_LOCK_WAIT;
    loop {
        let mut conn = db.get_connection().await?;
        let acquired: Option<String> = redis::cmd("SET")
            .arg(MIGRATION_LOCK_KEY)
            .arg(&token)
            .arg("NX")
            .arg("PX")
            .arg(MIGRATION_LOCK_TTL.as_millis() as u64)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                MediatorError::database_from_redis(
                    crate::error_codes::DB_OPERATION_ERROR,
                    "migrations".into(),
                    &e,
                    format!("Failed to take the migration lock: {e}"),
                )
            })?;
        if acquired.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(MediatorError::DatabaseError(
                crate::error_codes::DB_OPERATION_ERROR,
                "migrations".into(),
                format!(
                    "Another instance has held the migration lock ({MIGRATION_LOCK_KEY}) for over {}s",
                    MIGRATION_LOCK_WAIT.as_secs()
                ),
            ));
        }
        info!("Another instance is running database migrations; waiting for it");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let result = run_locked(db, config).await;

    let mut conn = db.get_connection().await?;
    if let Err(e) = RELEASE_LOCK
        .key(MIGRATION_LOCK_KEY)
        .arg(&token)
        .invoke_async::<i64>(&mut conn)
        .await
    {
        warn!("Couldn't release the migration lock (it expires on its own): {e}");
    }
    result
}

async fn run_locked(db: &Database, config: &RedisInitConfig) -> Result<(), MediatorError> {
    let migrations = all_migrations();

    // Bootstrap: detect legacy schema version system and seed applied set
    let applied = bootstrap_if_needed(db, &migrations).await?;

    let unknown = unknown_applied(&applied, &migrations);
    if !unknown.is_empty() {
        return Err(MediatorError::ConfigError(
            crate::error_codes::DB_CONFIG_INVALID,
            "migrations".into(),
            format!(
                "The database records schema migration(s) {unknown:?} that this mediator does not know: a newer mediator has migrated it. Run that version (or newer)."
            ),
        ));
    }

    let pending: Vec<&MigrationDef> = migrations
        .iter()
        .filter(|m| !applied.contains(&m.id))
        .collect();

    if pending.is_empty() {
        info!(
            "Database schema is up to date ({} migrations applied)",
            applied.len()
        );
        return Ok(());
    }

    info!("{} pending migration(s) to apply", pending.len());

    for migration in pending {
        info!(
            "Running migration {}: {} — {}",
            migration.id, migration.name, migration.description
        );

        migration.run(db, config).await?;

        // Record the migration as applied
        record_migration(db, migration.id, migration.name).await?;

        info!(
            "Migration {} ({}) applied successfully",
            migration.id, migration.name
        );
    }

    info!(
        "All migrations complete. {} total applied.",
        get_applied_ids(db).await?.len()
    );

    Ok(())
}

/// Applied migration ids this build does not define, in order.
fn unknown_applied(applied: &HashSet<u32>, migrations: &[MigrationDef]) -> Vec<u32> {
    let known: HashSet<u32> = migrations.iter().map(|m| m.id).collect();
    let mut unknown: Vec<u32> = applied.difference(&known).copied().collect();
    unknown.sort_unstable();
    unknown
}

/// Get the set of applied migration IDs from Redis.
async fn get_applied_ids(db: &Database) -> Result<HashSet<u32>, MediatorError> {
    let mut conn = db.get_connection().await?;

    let members: Vec<String> = redis::cmd("SMEMBERS")
        .arg(MIGRATIONS_SET_KEY)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::database_from_redis(
                error_codes::DB_OPERATION_ERROR,
                "migrations".into(),
                &e,
                format!("Failed to read {MIGRATIONS_SET_KEY}: {e}"),
            )
        })?;

    Ok(members.iter().filter_map(|s| s.parse().ok()).collect())
}

/// Record a migration as applied.
async fn record_migration(db: &Database, id: u32, name: &str) -> Result<(), MediatorError> {
    let mut conn = db.get_connection().await?;
    let now = crate::time::unix_timestamp_secs();

    let mut pipe = redis::pipe();
    pipe.cmd("SADD")
        .arg(MIGRATIONS_SET_KEY)
        .arg(id)
        .cmd("HSET")
        .arg(format!("SCHEMA_MIGRATION:{id}"))
        .arg("name")
        .arg(name)
        .arg("applied_at")
        .arg(now);
    db.query_each::<redis::Value>(&mut conn, pipe)
        .await
        .map(|_| ())
        .map_err(|e| {
            MediatorError::database_from_redis(
                error_codes::DB_OPERATION_ERROR,
                "migrations".into(),
                &e,
                format!("Failed to record migration {id}: {e}"),
            )
        })
}

/// Bootstrap from the legacy GLOBAL:SCHEMA_VERSION system.
///
/// If SCHEMA_MIGRATIONS doesn't exist yet but GLOBAL:SCHEMA_VERSION does,
/// we seed the applied set based on the legacy version. This ensures existing
/// databases don't re-run migrations that were already applied under the old system.
async fn bootstrap_if_needed(
    db: &Database,
    migrations: &[MigrationDef],
) -> Result<HashSet<u32>, MediatorError> {
    let mut conn = db.get_connection().await?;

    // Check if the new migration system is already in use
    let set_exists: bool = redis::cmd("EXISTS")
        .arg(MIGRATIONS_SET_KEY)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::database_from_redis(
                error_codes::DB_OPERATION_ERROR,
                "migrations".into(),
                &e,
                format!("Failed to check {MIGRATIONS_SET_KEY}: {e}"),
            )
        })?;

    if set_exists {
        // New system already active — just return the applied set
        return get_applied_ids(db).await;
    }

    // Check for legacy schema version
    let legacy_version: Option<String> = redis::cmd("HGET")
        .arg("GLOBAL")
        .arg("SCHEMA_VERSION")
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::database_from_redis(
                error_codes::DB_OPERATION_ERROR,
                "migrations".into(),
                &e,
                format!("Failed to read legacy SCHEMA_VERSION: {e}"),
            )
        })?;

    if let Some(legacy_str) = legacy_version {
        // Existing database with legacy versioning — seed the migration set
        let legacy_ver = Version::parse(&legacy_str).unwrap_or_else(|_| {
            warn!(
                "Could not parse legacy SCHEMA_VERSION '{}', treating as 0.0.0",
                legacy_str
            );
            Version::new(0, 0, 0)
        });

        info!(
            "Bootstrapping migration system from legacy SCHEMA_VERSION {}",
            legacy_ver
        );

        // Mark all migrations that would have already been applied at this version
        let mut seeded = HashSet::new();
        for migration in migrations {
            if let Some(lv) = migration.legacy_version
                && let Ok(migration_ver) = Version::parse(lv)
                && legacy_ver >= migration_ver
            {
                info!(
                    "  Seeding migration {} ({}) — already applied at legacy version {}",
                    migration.id, migration.name, lv
                );
                record_migration(db, migration.id, migration.name).await?;
                seeded.insert(migration.id);
            }
        }

        // Remove legacy version field — migration system is now authoritative
        redis::cmd("HDEL")
            .arg("GLOBAL")
            .arg("SCHEMA_VERSION")
            .exec_async(&mut conn)
            .await
            .map_err(|e| {
                MediatorError::database_from_redis(
                    error_codes::DB_OPERATION_ERROR,
                    "migrations".into(),
                    &e,
                    format!("Failed to remove legacy SCHEMA_VERSION: {e}"),
                )
            })?;

        info!(
            "Bootstrap complete: {} migrations seeded, legacy SCHEMA_VERSION removed",
            seeded.len()
        );

        Ok(seeded)
    } else {
        // Fresh database — no legacy version, no migrations applied yet
        info!("Fresh database detected — no migrations applied yet");
        Ok(HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_applied_migration_this_build_lacks_is_reported() {
        let migrations = all_migrations();
        let mut applied: HashSet<u32> = migrations.iter().map(|m| m.id).collect();
        assert!(unknown_applied(&applied, &migrations).is_empty());
        applied.insert(9_999);
        assert_eq!(unknown_applied(&applied, &migrations), vec![9_999]);
    }
}
