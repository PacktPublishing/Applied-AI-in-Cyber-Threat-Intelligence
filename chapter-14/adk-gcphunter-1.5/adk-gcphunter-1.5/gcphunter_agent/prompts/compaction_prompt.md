# Output Compaction Instruction

Your previous hunt results exceeded size limits and caused a validation error.

## Task
Reduce raw_output fields while preserving critical information:

### PRESERVE (Required):
- All TTP IDs and names
- All log entry counts
- Critical security findings (high severity only)
- Unique IOCs (IP addresses, domains, usernames, file paths)
- Execution status for each command
- Timestamps of key events

### COMPRESS (Required):
- Remove verbose JSON logs from raw_output
- Keep only summary statistics
- Limit raw_output to essential findings
- Each raw_output field MUST be under 45,000 characters

### ADD VERIFICATION NOTICE
Set the truncation_notice field:

```json
{
  "truncation_notice": "Results were semantically compacted due to size constraints. Full details available in hunt_results/*.json files. Run verification commands to see complete outputs."
}
```

### ADD VERIFICATION COMMANDS
Populate verification_commands array with exact gcloud commands the analyst can run:

```json
{
  "verification_commands": [
    "gcloud logging read 'protoPayload.methodName=\"SetIamPolicy\"' --limit=1000 --format=json --project=PROJECT_ID",
    "gcloud logging read 'resource.type=\"gce_instance\" AND protoPayload.methodName=\"v1.compute.instances.insert\"' --limit=500 --format=json --project=PROJECT_ID"
  ]
}
```

Extract these commands from the hunt_commands that were executed.

## Output Format
Return the complete FinalHuntReport schema with:
- Compacted raw_output fields (under 45,000 chars each)
- truncation_notice field populated
- verification_commands array populated with exact gcloud commands
- All other fields preserved

Focus on actionable intelligence over raw data volume.
