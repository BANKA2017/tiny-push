CREATE TRIGGER v2_message_cache_limit
    AFTER INSERT ON v2_message_cache
BEGIN
    DELETE FROM v2_message_cache
    WHERE mid = (
        SELECT mid
        FROM v2_message_cache
        WHERE uaid = NEW.uaid
        ORDER BY mid DESC
        LIMIT 1
    OFFSET {V2TriggerCacheLimit}
        );
END