-- 0007_filter_catalog_v2.sql — filter ids and levels renamed (Relaxed / Balanced / Strict)

UPDATE profile_filters SET ref = 'oisd-big', level = 'on' WHERE kind = 'filter' AND ref = 'ads' AND level = 'oisd';
UPDATE profile_filters SET level = CASE level
    WHEN 'light' THEN 'relaxed' WHEN 'normal' THEN 'balanced' ELSE 'strict' END
    WHERE kind = 'filter' AND ref = 'ads';
UPDATE profile_filters SET level = CASE level WHEN 'full' THEN 'strict' ELSE 'balanced' END
    WHERE kind = 'filter' AND ref = 'malware';
UPDATE profile_filters SET level = CASE level WHEN 'strict' THEN 'strict' ELSE 'balanced' END
    WHERE kind = 'filter' AND ref = 'adult';
UPDATE profile_filters SET level = 'strict' WHERE kind = 'filter' AND ref = 'gambling';
UPDATE profile_filters SET ref = 'scams' WHERE kind = 'filter' AND ref = 'fakes';
UPDATE profile_filters SET ref = 'tlds' WHERE kind = 'filter' AND ref = 'spamtlds';
UPDATE profile_filters SET ref = 'vpndns', level = CASE level WHEN 'doh' THEN 'dns' ELSE 'all' END
    WHERE kind = 'filter' AND ref = 'bypass';
