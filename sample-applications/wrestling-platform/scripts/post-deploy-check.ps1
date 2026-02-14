param(
    [string]$WebBaseUrl = "https://wrestling-platform-web.onrender.com",
    [string]$ApiBaseUrl = "https://wrestling-platform-api.onrender.com"
)

$ErrorActionPreference = "Stop"

$WebBaseUrl = $WebBaseUrl.TrimEnd('/')
$ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')

$checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail
    )

    $checks.Add([pscustomobject]@{
            Name   = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Parse-JsonSafe {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    try {
        return $Text | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Invoke-Http {
    param(
        [string]$Method,
        [string]$Url,
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 120
    )

    $requestArgs = @{
        Method     = $Method
        Uri        = $Url
        Headers    = $Headers
        UseBasicParsing = $true
        TimeoutSec = $TimeoutSec
    }

    if ($null -ne $Body) {
        $requestArgs.ContentType = "application/json"
        $requestArgs.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $resp = Invoke-WebRequest @requestArgs
        $content = $resp.Content
        return [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Body       = $content
            Json       = Parse-JsonSafe $content
        }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            $statusCode = [int]$response.StatusCode
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $body = $reader.ReadToEnd()
            return [pscustomobject]@{
                StatusCode = $statusCode
                Body       = $body
                Json       = Parse-JsonSafe $body
            }
        }

        throw
    }
}

function Assert-Status {
    param(
        [string]$Step,
        [object]$Response,
        [int[]]$Expected
    )

    if ($Expected -contains $Response.StatusCode) {
        return
    }

    throw "[$Step] Expected status $($Expected -join ',') but got $($Response.StatusCode). Body: $($Response.Body)"
}

$runId = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$password = "S3curePass!"

$athlete1Email = "deploy-ath1-$runId@example.com"
$athlete2Email = "deploy-ath2-$runId@example.com"
$coachEmail = "deploy-coach-$runId@example.com"

$athlete1 = @{}
$athlete2 = @{}
$coach = @{}
$flow = @{}

try {
    # 2) Health checks
    $webHealth = Invoke-Http -Method GET -Url "$WebBaseUrl/healthz"
    Assert-Status -Step "Web health" -Response $webHealth -Expected @(200)
    Add-Check -Name "2. Health checks" -Passed $true -Detail "Web and API /healthz responded 200."

    $apiHealth = Invoke-Http -Method GET -Url "$ApiBaseUrl/healthz"
    Assert-Status -Step "API health" -Response $apiHealth -Expected @(200)

    # 3) UI route smoke test
    $uiRoutes = @("/", "/athlete", "/coach", "/admin")
    $uiStatuses = @()
    foreach ($route in $uiRoutes) {
        $resp = Invoke-Http -Method GET -Url "$WebBaseUrl$route"
        Assert-Status -Step "UI route $route" -Response $resp -Expected @(200)
        $uiStatuses += "$route=$($resp.StatusCode)"

        if ($route -eq "/") {
            $homeBody = $resp.Body
        }
    }
    Add-Check -Name "3. UI routes" -Passed $true -Detail ($uiStatuses -join ", ")

    # 4) API connectivity from web
    $homeErrorSignals = @(
        "Unable to load dashboard data",
        "API service is unreachable",
        "No events available yet"
    )

    $hasConnectivityIssue = $true
    $signalHits = @()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $homeRespRetry = Invoke-Http -Method GET -Url "$WebBaseUrl/"
        Assert-Status -Step "Home route retry $attempt" -Response $homeRespRetry -Expected @(200)

        $homeBody = $homeRespRetry.Body
        $signalHits = @($homeErrorSignals | Where-Object { $homeBody -like "*$_*" })
        $hasConnectivityIssue = @($signalHits | Where-Object { $_ -ne "No events available yet" }).Count -gt 0

        if (-not $hasConnectivityIssue) {
            break
        }

        Start-Sleep -Seconds (2 * $attempt)
    }

    $connectivityDetail = if ($signalHits.Count -gt 0) { "Signals seen: " + ($signalHits -join ", ") } else { "Home page rendered without API error signals." }
    Add-Check -Name "4. Web->API connectivity" -Passed (-not $hasConnectivityIssue) -Detail $connectivityDetail


    # 5) Auth flow (register/login/refresh/logout)
    $regAth1 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/users/register" -Body @{
        email      = $athlete1Email
        password   = $password
        role       = "Athlete"
        phoneNumber = "+16145550101"
    }
    Assert-Status -Step "Register athlete1" -Response $regAth1 -Expected @(201)
    $athlete1.UserId = [string]$regAth1.Json.id

    $loginAth1 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/login" -Body @{
        email    = $athlete1Email
        password = $password
    }
    Assert-Status -Step "Login athlete1" -Response $loginAth1 -Expected @(200)

    $athlete1.AccessToken = [string]$loginAth1.Json.accessToken
    $athlete1.RefreshToken = [string]$loginAth1.Json.refreshToken

    $refreshAth1 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/refresh" -Body @{ refreshToken = $athlete1.RefreshToken }
    Assert-Status -Step "Refresh athlete1" -Response $refreshAth1 -Expected @(200)

    $newAccessToken = [string]$refreshAth1.Json.accessToken
    $newRefreshToken = [string]$refreshAth1.Json.refreshToken

    $logoutAth1 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/logout" -Headers @{ Authorization = "Bearer $newAccessToken" }
    Assert-Status -Step "Logout athlete1" -Response $logoutAth1 -Expected @(200)

    $reuseOldRefresh = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/refresh" -Body @{ refreshToken = $athlete1.RefreshToken }
    $reuseBlocked = $reuseOldRefresh.StatusCode -eq 401

    # Re-login athlete1 for remaining checks
    $loginAth1b = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/login" -Body @{
        email    = $athlete1Email
        password = $password
    }
    Assert-Status -Step "Re-login athlete1" -Response $loginAth1b -Expected @(200)
    $athlete1.AccessToken = [string]$loginAth1b.Json.accessToken

    Add-Check -Name "5. Auth flow" -Passed $reuseBlocked -Detail "Register/login/refresh/logout succeeded; old refresh token blocked=$reuseBlocked."

    # second athlete setup
    $regAth2 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/users/register" -Body @{
        email      = $athlete2Email
        password   = $password
        role       = "Athlete"
        phoneNumber = "+16145550103"
    }
    Assert-Status -Step "Register athlete2" -Response $regAth2 -Expected @(201)
    $athlete2.UserId = [string]$regAth2.Json.id

    $loginAth2 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/login" -Body @{
        email    = $athlete2Email
        password = $password
    }
    Assert-Status -Step "Login athlete2" -Response $loginAth2 -Expected @(200)
    $athlete2.AccessToken = [string]$loginAth2.Json.accessToken

    # coach setup
    $regCoach = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/users/register" -Body @{
        email      = $coachEmail
        password   = $password
        role       = "Coach"
        phoneNumber = "+16145550102"
    }
    Assert-Status -Step "Register coach" -Response $regCoach -Expected @(201)
    $coach.UserId = [string]$regCoach.Json.id

    $loginCoach = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/auth/login" -Body @{
        email    = $coachEmail
        password = $password
    }
    Assert-Status -Step "Login coach" -Response $loginCoach -Expected @(200)
    $coach.AccessToken = [string]$loginCoach.Json.accessToken

    # 6) Core user flows
    $birth = (Get-Date).AddYears(-16).ToUniversalTime().ToString("o")

    $athlete1ProfileResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/profiles/athletes" -Headers @{ Authorization = "Bearer $($athlete1.AccessToken)" } -Body @{
        userAccountId  = $athlete1.UserId
        firstName      = "Eli"
        lastName       = "Turner"
        dateOfBirthUtc = $birth
        state          = "OH"
        city           = "Columbus"
        schoolOrClubName = "Central Wrestling Club"
        grade          = 10
        weightClass    = 132
        level          = "HighSchool"
    }
    Assert-Status -Step "Create athlete1 profile" -Response $athlete1ProfileResp -Expected @(201)
    $athlete1.ProfileId = [string]$athlete1ProfileResp.Json.id

    $athlete2ProfileResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/profiles/athletes" -Headers @{ Authorization = "Bearer $($athlete2.AccessToken)" } -Body @{
        userAccountId  = $athlete2.UserId
        firstName      = "Noah"
        lastName       = "Miller"
        dateOfBirthUtc = $birth
        state          = "OH"
        city           = "Columbus"
        schoolOrClubName = "Metro Wrestling"
        grade          = 10
        weightClass    = 132
        level          = "HighSchool"
    }
    Assert-Status -Step "Create athlete2 profile" -Response $athlete2ProfileResp -Expected @(201)
    $athlete2.ProfileId = [string]$athlete2ProfileResp.Json.id

    $coachProfileResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/profiles/coaches" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        userAccountId = $coach.UserId
        firstName     = "Mason"
        lastName      = "Reed"
        state         = "OH"
        city          = "Columbus"
        bio           = "High-tempo neutral offense coach"
    }
    Assert-Status -Step "Create coach profile" -Response $coachProfileResp -Expected @(201)
    $coach.ProfileId = [string]$coachProfileResp.Json.id

    $teamResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/teams" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        name = "Capital Elite Wrestling $runId"
        type = "Club"
        state = "OH"
        city = "Columbus"
    }
    Assert-Status -Step "Create team" -Response $teamResp -Expected @(201)
    $flow.TeamId = [string]$teamResp.Json.id

    $assocResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/coaches/$($coach.ProfileId)/associations" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        athleteProfileId = $athlete1.ProfileId
        teamId = $flow.TeamId
        roleTitle = "Head Coach"
        isPrimary = $true
    }
    Assert-Status -Step "Create coach association" -Response $assocResp -Expected @(201)

    Add-Check -Name "6. Core user flows" -Passed $true -Detail "Athlete profiles, coach profile, team, and coach association created."

    # 7) Event lifecycle
    $startUtc = (Get-Date).ToUniversalTime().AddDays(7).ToString("o")
    $endUtc = (Get-Date).ToUniversalTime().AddDays(8).ToString("o")

    $eventResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        name = "Render Validation Open $runId"
        organizerType = "Club"
        organizerId = $flow.TeamId
        state = "OH"
        city = "Columbus"
        venue = "Metro Sports Complex"
        startUtc = $startUtc
        endUtc = $endUtc
        entryFeeCents = 3500
        isPublished = $true
    }
    Assert-Status -Step "Create event" -Response $eventResp -Expected @(201)
    $flow.EventId = [string]$eventResp.Json.id

    $divisionResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/divisions" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        level = "HighSchool"
        weightClass = 132
        name = "High School 132"
    }
    Assert-Status -Step "Create division" -Response $divisionResp -Expected @(201)
    $flow.DivisionId = [string]$divisionResp.Json.id

    Add-Check -Name "7. Event lifecycle" -Passed $true -Detail "Event and division created. Bracket generation validated in checklist item 9 after registrations."

    # 8) Registration flow (search + free-agent)
    $searchResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/events/search?state=OH&city=Columbus&level=HighSchool"
    Assert-Status -Step "Search events" -Response $searchResp -Expected @(200)

    $foundEvent = $false
    if ($searchResp.Json) {
        foreach ($e in @($searchResp.Json)) {
            if ([string]$e.id -eq $flow.EventId) {
                $foundEvent = $true
            }
        }
    }

    $regAth1 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/registrations" -Headers @{ Authorization = "Bearer $($athlete1.AccessToken)" } -Body @{
        athleteProfileId = $athlete1.ProfileId
        teamId = $null
        isFreeAgent = $true
    }
    Assert-Status -Step "Register athlete1" -Response $regAth1 -Expected @(201)

    $regAth2 = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/registrations" -Headers @{ Authorization = "Bearer $($athlete2.AccessToken)" } -Body @{
        athleteProfileId = $athlete2.ProfileId
        teamId = $null
        isFreeAgent = $true
    }
    Assert-Status -Step "Register athlete2" -Response $regAth2 -Expected @(201)

    $freeAgentListResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/events/$($flow.EventId)/free-agents" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" }
    Assert-Status -Step "Get free agents" -Response $freeAgentListResp -Expected @(200)

    $flow.FreeAgentRegistrationId = $null
    foreach ($fa in @($freeAgentListResp.Json)) {
        if ([string]$fa.athleteId -eq $athlete1.ProfileId) {
            $flow.FreeAgentRegistrationId = [string]$fa.id
        }
    }

    if ([string]::IsNullOrWhiteSpace($flow.FreeAgentRegistrationId)) {
        throw "Unable to find athlete1 free-agent registration in listing."
    }

    $inviteResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/free-agents/$($flow.FreeAgentRegistrationId)/invite" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        teamId = $flow.TeamId
        message = "Join our lineup"
    }
    Assert-Status -Step "Invite free agent" -Response $inviteResp -Expected @(201)

    Add-Check -Name "8. Registration + free-agent" -Passed $foundEvent -Detail "Event searchable=$foundEvent; athlete registrations + invite succeeded."

    # Notifications subscription before match operations
    $subInHole = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/notifications/subscriptions" -Headers @{ Authorization = "Bearer $($athlete1.AccessToken)" } -Body @{
        userAccountId = $athlete1.UserId
        tournamentEventId = $flow.EventId
        athleteProfileId = $athlete1.ProfileId
        eventType = "InTheHole"
        channel = "Email"
        destination = "athlete1+$runId@example.com"
    }
    Assert-Status -Step "Subscribe InTheHole" -Response $subInHole -Expected @(201)

    $subResult = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/notifications/subscriptions" -Headers @{ Authorization = "Bearer $($athlete1.AccessToken)" } -Body @{
        userAccountId = $athlete1.UserId
        tournamentEventId = $flow.EventId
        athleteProfileId = $athlete1.ProfileId
        eventType = "MatchResult"
        channel = "Email"
        destination = "athlete1+$runId@example.com"
    }
    Assert-Status -Step "Subscribe MatchResult" -Response $subResult -Expected @(201)

    # Bracket operations now that we have entrants
    $generateResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/brackets/generate" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        level = "HighSchool"
        weightClass = 132
        mode = "Seeded"
        divisionId = $flow.DivisionId
    }
    Assert-Status -Step "Generate bracket" -Response $generateResp -Expected @(200)

    $bracketsResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/events/$($flow.EventId)/brackets"
    Assert-Status -Step "Get brackets" -Response $bracketsResp -Expected @(200)

    $firstBracket = @($bracketsResp.Json)[0]
    if (-not $firstBracket) {
        throw "No bracket returned."
    }

    $matches = @($firstBracket.matches)
    if ($matches.Count -eq 0) {
        throw "Bracket has zero matches."
    }

    $selectedMatch = $matches | Where-Object { $_.athleteAId -and $_.athleteBId } | Select-Object -First 1
    if (-not $selectedMatch) {
        $selectedMatch = $matches | Select-Object -First 1
    }

    $flow.MatchId = [string]$selectedMatch.id
    $winnerAthleteId = if ($selectedMatch.athleteAId) { [string]$selectedMatch.athleteAId } else { $athlete1.ProfileId }

    # 9) Match result + rankings + stats
    $assignResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/matches/$($flow.MatchId)/assign-mat" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        matNumber = "Mat 1"
        scheduledUtc = (Get-Date).ToUniversalTime().AddDays(7).ToString("o")
        markInTheHole = $true
    }
    Assert-Status -Step "Assign mat" -Response $assignResp -Expected @(200)

    $resultResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/matches/$($flow.MatchId)/result" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        winnerAthleteId = $winnerAthleteId
        score = "10-3"
        resultMethod = "Decision"
        pointsForWinner = 10
        pointsForLoser = 3
    }
    Assert-Status -Step "Record result" -Response $resultResp -Expected @(200)

    $rankResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/rankings?level=HighSchool&state=OH&take=100"
    Assert-Status -Step "Get rankings" -Response $rankResp -Expected @(200)

    $winnerInRankings = $false
    foreach ($r in @($rankResp.Json)) {
        if ([string]$r.athleteProfileId -eq $winnerAthleteId) {
            $winnerInRankings = $true
        }
    }

    $winnerUserToken = if ($winnerAthleteId -eq $athlete1.ProfileId) { $athlete1.AccessToken } else { $athlete2.AccessToken }
    $statsResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/athletes/$winnerAthleteId/stats/history" -Headers @{ Authorization = "Bearer $winnerUserToken" }
    Assert-Status -Step "Get stats history" -Response $statsResp -Expected @(200)
    $statsCount = @($statsResp.Json).Count

    Add-Check -Name "9. Results + rankings + stats" -Passed ($winnerInRankings -and $statsCount -gt 0) -Detail "Winner in rankings=$winnerInRankings; stats snapshots=$statsCount."

    # 10) Notifications path
    $msgResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/notifications/messages/$($athlete1.UserId)" -Headers @{ Authorization = "Bearer $($athlete1.AccessToken)" }
    Assert-Status -Step "Get notification messages" -Response $msgResp -Expected @(200)
    $msgCount = @($msgResp.Json).Count

    Add-Check -Name "10. Notifications" -Passed ($msgCount -gt 0) -Detail "Subscriptions saved and message feed count=$msgCount."

    # stream control check (part of core ops)
    $streamCreateResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/events/$($flow.EventId)/streams" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{
        matchId = $flow.MatchId
        deviceName = "Table Cam 1"
    }
    Assert-Status -Step "Create stream" -Response $streamCreateResp -Expected @(201)
    $flow.StreamId = [string]$streamCreateResp.Json.id

    $streamLiveResp = Invoke-Http -Method POST -Url "$ApiBaseUrl/api/streams/$($flow.StreamId)/status" -Headers @{ Authorization = "Bearer $($coach.AccessToken)" } -Body @{ status = "Live" }
    Assert-Status -Step "Set stream live" -Response $streamLiveResp -Expected @(200)

    $activeStreamsResp = Invoke-Http -Method GET -Url "$ApiBaseUrl/api/events/$($flow.EventId)/streams/active"
    Assert-Status -Step "Get active streams" -Response $activeStreamsResp -Expected @(200)
    $activeStreamsCount = @($activeStreamsResp.Json).Count
    Add-Check -Name "Streaming active path" -Passed ($activeStreamsCount -gt 0) -Detail "Active streams for event=$activeStreamsCount."

    # 1) deploy version check is manual from Render UI
    Add-Check -Name "1. Deploy versions" -Passed $false -Detail "Manual check required in Render UI (service -> Events should show latest commit 899db4f web / 33d8bb0+ API lineage)."

    # 11) Observability/alerts manual
    Add-Check -Name "11. Observability + alerts" -Passed $false -Detail "Manual in Render UI: Alerts, log retention, and incident notifications cannot be verified from public endpoints."

    # 12) Recovery readiness manual
    Add-Check -Name "12. Recovery readiness" -Passed $false -Detail "Manual in Render UI: rollback target selection and DB backup/export policy need account-level verification."

}
catch {
    Add-Check -Name "Run status" -Passed $false -Detail $_.Exception.Message
}

$passed = @($checks | Where-Object { $_.Passed }).Count
$total = $checks.Count

Write-Output "POST_DEPLOY_CHECKLIST_RESULT"
Write-Output "WEB_URL=$WebBaseUrl"
Write-Output "API_URL=$ApiBaseUrl"
Write-Output "PASSED=$passed/$total"
Write-Output ""

foreach ($check in $checks) {
    $status = if ($check.Passed) { "PASS" } else { "FAIL/MANUAL" }
    Write-Output ("[{0}] {1} :: {2}" -f $status, $check.Name, $check.Detail)
}


