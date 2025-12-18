-- ======================================================
-- Exfiliator - LogRhythm (LogMart SQL / WebUI Search)
-- Use as a template inside Investigations or AIE rules.
-- ======================================================

-- ---------- PARAMETERS ----------
DECLARE @StartTime DATETIME = DATEADD(HOUR, -24, GETUTCDATE());
DECLARE @EndTime   DATETIME = GETUTCDATE();
DECLARE @TestPorts TABLE (Port INT);
INSERT INTO @TestPorts VALUES (5001), (5002), (8080), (8443);

-- ---------- 1) Network sessions from Exfiliator hosts ----------
SELECT
    dbo.LRDateTime(App.AppStartTime)   AS [Time],
    App.NormalizedDescription          AS [EventName],
    App.LogSourceName                  AS [LogSource],
    App.ImpactedHostName               AS [Host],
    App.ImpactedIP                     AS [SourceIP],
    App.TargetIP                       AS [DestIP],
    App.TargetPort                     AS [DestPort],
    App.Protocol,
    App.VendorMsgID                    AS [DeviceAction],
    App.OriginUser                     AS [User],
    App.ConsoleMessage                 AS [RawMessage]
FROM dbo.lrappl EventApp WITH (NOLOCK)
    INNER JOIN dbo.vwAIEvent App WITH (NOLOCK) ON EventApp.AppID = App.AppID
    INNER JOIN @TestPorts TP ON App.TargetPort = TP.Port
WHERE App.AppStartTime BETWEEN @StartTime AND @EndTime
  AND (App.OriginProcessName LIKE '%python%' OR App.ConsoleMessage LIKE '%/upload%')
ORDER BY App.AppStartTime DESC;

-- ---------- 2) DNS queries carrying PSK ----------
SELECT
    dbo.LRDateTime(App.AppStartTime) AS [Time],
    App.NormalizedDescription        AS [EventName],
    App.ImpactedHostName             AS [Host],
    App.TargetHostName               AS [DNSQuery],
    App.ConsoleMessage               AS [RawMessage]
FROM dbo.vwAIEvent App WITH (NOLOCK)
WHERE App.AppStartTime BETWEEN @StartTime AND @EndTime
  AND App.NormalizedDescription LIKE '%DNS%'
  AND App.TargetHostName LIKE '%psk-%'
ORDER BY App.AppStartTime DESC;

-- ---------- 3) Process creation telemetry (Windows auditing) ----------
SELECT
    dbo.LRDateTime(App.AppStartTime) AS [Time],
    App.ImpactedHostName             AS [Host],
    App.OriginUser                   AS [User],
    App.OriginProcessName            AS [Process],
    App.ConsoleMessage               AS [CommandLine]
FROM dbo.vwAIEvent App WITH (NOLOCK)
WHERE App.AppStartTime BETWEEN @StartTime AND @EndTime
  AND App.NormalizedDescription = 'Process Start'
  AND App.OriginProcessName LIKE '%python%'
ORDER BY App.AppStartTime DESC;
