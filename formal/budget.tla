---------------------------- MODULE budget ----------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Replicas, Total
VARIABLES remaining, granted, consumed, reserved, crashed

TypeOK ==
  /\ remaining \in 0..Total
  /\ granted \in [Replicas -> 0..Total]

\* Safety: total spend never exceeds the budget.
NoOverspend ==
  remaining + (\* sum of granted \*) 0 <= Total

\* Grants are deducted BEFORE being handed out - this is the crux.
Acquire(r, amount) ==
  /\ ~crashed[r]
  /\ amount <= remaining
  /\ remaining' = remaining - amount
  /\ granted' = [granted EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<consumed, reserved, crashed>>

\* TODO week 3-5: Spend, Release, Expire, Crash, Partition, Init, Next, Spec
=============================================================================
