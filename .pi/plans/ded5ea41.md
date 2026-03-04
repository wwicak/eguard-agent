{
  "id": "ded5ea41",
  "title": "Polish NN runtime reliability: dynamic embedding dimensions + eval parity + validation",
  "status": "completed",
  "created_at": "2026-03-03T13:28:08.374Z",
  "assigned_to_session": "a0049ac6-454f-41e1-a7f0-f5c9635ae10b",
  "steps": [
    {
      "id": 1,
      "text": "Update Go server signature ML runtime to use model-driven embedding dimensions for shallow_nn features instead of fixed constants",
      "done": true
    },
    {
      "id": 2,
      "text": "Update offline/adversarial eval scoring path to use model-driven embedding dimensions (from artifact metadata or inferred features)",
      "done": true
    },
    {
      "id": 3,
      "text": "Run regression (gofmt, go tests, python compile) plus smoke validation with non-default embedding dims",
      "done": true
    },
    {
      "id": 4,
      "text": "Document improvements in tasks/todo.md and operations guide",
      "done": true
    }
  ]
}
