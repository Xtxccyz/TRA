param(
  [Parameter(Mandatory = $true)][string]$SessionId,
  [Parameter(Mandatory = $true)][string]$OutputStem,
  [int]$InitialSeq = 0,
  [int]$MaxIterations = 80
)

$jsonl = "$OutputStem.jsonl"
$finalPath = "$OutputStem-final.json"
$taskPath = "$OutputStem-task.json"
$after = [Math]::Max(0, $InitialSeq)

for ($i = 0; $i -lt $MaxIterations; $i++) {
  $uri = "http://127.0.0.1:8000/api/v1/workbench/sessions/$SessionId/analysis/wait?after_seq=$after&timeout_seconds=30"
  try {
    $response = Invoke-RestMethod $uri -TimeoutSec 40
  } catch {
    Write-Output "wait-error: $($_.Exception.Message)"
    Start-Sleep -Seconds 2
    continue
  }
  $record = @{
    iteration = $i
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    changed = $response.changed
    next_seq = $response.next_seq
    progress = $response.progress
    context = @{
      state = $response.context.state
      task_lifecycle = $response.context.task_lifecycle
      analysis_class = $response.context.analysis_class
      task_outcome = $response.context.task_outcome
      failure = $response.context.failure
      elapsed_ms = $response.context.elapsed_ms
    }
  }
  ($record | ConvertTo-Json -Depth 12 -Compress) | Add-Content -LiteralPath $jsonl
  $progress = $response.progress
  Write-Output ("[{0}] changed={1} state={2} stage={3} seq={4} evidence={5} verified={6}" -f $i, $response.changed, $response.context.state, $progress.stage, $response.next_seq, $progress.new_evidence_since_last, $progress.mechanisms_verified)
  if ([int]$response.next_seq -gt $after) { $after = [int]$response.next_seq }
  if ($response.context.state -in @('ANALYSIS_READY', 'ANALYSIS_FAILED', 'ANALYSIS_CANCELLED')) { break }
}

$status = Invoke-RestMethod "http://127.0.0.1:8000/api/v1/workbench/sessions/$SessionId/analysis/status"
$status | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $finalPath
if ($status.active_task_id) {
  try {
    $task = Invoke-RestMethod "http://127.0.0.1:8000/api/v1/workbench/tasks/$($status.active_task_id)"
    $task | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $taskPath
  } catch {
    Write-Output "task-state-error: $($_.Exception.Message)"
  }
}
Write-Output ("FINAL state={0} lifecycle={1} class={2} outcome={3} elapsed_ms={4}" -f $status.state, $status.task_lifecycle, $status.analysis_class, $status.task_outcome, $status.elapsed_ms)
