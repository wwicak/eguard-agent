{
  "id": "feb2b00c",
  "title": "Publish real threat intel bundle release",
  "status": "active",
  "created_at": "2026-03-16T04:42:09.648Z",
  "assigned_to_session": "479f47fd-ec11-4c2d-98dd-d36a87ccb4a3",
  "steps": [
    {
      "id": 1,
      "text": "Assess PR #2 mergeability and current main branch state for wwicak/eguard-agent.",
      "done": false
    },
    {
      "id": 2,
      "text": "Update tasks/todo.md with a short release plan and outcome notes.",
      "done": false
    },
    {
      "id": 3,
      "text": "Get the build-bundle fix onto main using GitHub CLI or git without including local task artifacts.",
      "done": false
    },
    {
      "id": 4,
      "text": "Trigger build-bundle.yml on main with promote_release=true and monitor until the GitHub release is created.",
      "done": false
    },
    {
      "id": 5,
      "text": "Capture the created release URL/version and summarize the result.",
      "done": false
    }
  ]
}

Merge the workflow fix into wwicak/eguard-agent main in a safe way, then trigger the build-bundle workflow in release mode and confirm that the GitHub release is created.
