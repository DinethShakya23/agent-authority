# Go SDK

```go
c, _ := agentsdk.New(agentsdk.Config{
    ControlPlane: "https://agentd:8443",
    WSO2Token:    token,     // obtained via WSO2 Agent ID + Secret
})
exec, _ := c.StartExecution(ctx, agentsdk.Intent{Type: "create_purchase_orders"})
resp, err := exec.Post(ctx, "/api/purchase-orders", body)   // signed automatically
fmt.Println(exec.BudgetRemaining())
```

Published as its own Go module so agent authors do not depend on the
control plane.
