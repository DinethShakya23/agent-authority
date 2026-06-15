---------------------------- MODULE budget ----------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Replicas, Total
VARIABLES remaining, granted, consumed, reserved, crashed

vars == <<remaining, granted, consumed, reserved, crashed>>

TypeOK ==
  /\ remaining \in 0..Total
  /\ granted \in [Replicas -> 0..Total]
  /\ consumed \in [Replicas -> 0..Total]
  /\ reserved \in [Replicas -> 0..Total]
  /\ crashed \in [Replicas -> BOOLEAN]

SumOver(f) == LET S == DOMAIN f
              IN IF S = {} THEN 0
                 ELSE LET s == CHOOSE x \in S : TRUE
                      IN f[s] + SumOver([x \in S \ {s} |-> f[x]])

NoOverspend ==
  remaining + SumOver(granted) + SumOver(consumed) = Total

SafetyInvariant ==
  SumOver(consumed) <= Total

Init ==
  /\ remaining = Total
  /\ granted = [r \in Replicas |-> 0]
  /\ consumed = [r \in Replicas |-> 0]
  /\ reserved = [r \in Replicas |-> 0]
  /\ crashed = [r \in Replicas |-> FALSE]

Acquire(r, amount) ==
  /\ ~crashed[r]
  /\ amount > 0
  /\ amount <= remaining
  /\ remaining' = remaining - amount
  /\ granted' = [granted EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<consumed, reserved, crashed>>

Spend(r, amount) ==
  /\ ~crashed[r]
  /\ amount > 0
  /\ amount <= granted[r]
  /\ granted' = [granted EXCEPT ![r] = @ - amount]
  /\ consumed' = [consumed EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<remaining, reserved, crashed>>

Reserve(r, amount) ==
  /\ ~crashed[r]
  /\ amount > 0
  /\ amount <= granted[r]
  /\ granted' = [granted EXCEPT ![r] = @ - amount]
  /\ reserved' = [reserved EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<remaining, consumed, crashed>>

CommitReserve(r, amount) ==
  /\ ~crashed[r]
  /\ amount > 0
  /\ amount <= reserved[r]
  /\ reserved' = [reserved EXCEPT ![r] = @ - amount]
  /\ consumed' = [consumed EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<remaining, granted, crashed>>

ReleaseReserve(r, amount) ==
  /\ ~crashed[r]
  /\ amount > 0
  /\ amount <= reserved[r]
  /\ reserved' = [reserved EXCEPT ![r] = @ - amount]
  /\ granted' = [granted EXCEPT ![r] = @ + amount]
  /\ UNCHANGED <<remaining, consumed, crashed>>

Release(r) ==
  /\ ~crashed[r]
  /\ granted[r] > 0
  /\ remaining' = remaining + granted[r]
  /\ granted' = [granted EXCEPT ![r] = 0]
  /\ UNCHANGED <<consumed, reserved, crashed>>

Crash(r) ==
  /\ ~crashed[r]
  /\ crashed' = [crashed EXCEPT ![r] = TRUE]
  /\ UNCHANGED <<remaining, granted, consumed, reserved>>

Expire(r) ==
  /\ crashed[r]
  /\ remaining' = remaining + granted[r] + reserved[r]
  /\ granted' = [granted EXCEPT ![r] = 0]
  /\ reserved' = [reserved EXCEPT ![r] = 0]
  /\ crashed' = [crashed EXCEPT ![r] = FALSE]
  /\ UNCHANGED consumed

Next ==
  \E r \in Replicas :
    \/ \E a \in 1..Total : Acquire(r, a)
    \/ \E a \in 1..Total : Spend(r, a)
    \/ \E a \in 1..Total : Reserve(r, a)
    \/ \E a \in 1..Total : CommitReserve(r, a)
    \/ \E a \in 1..Total : ReleaseReserve(r, a)
    \/ Release(r)
    \/ Crash(r)
    \/ Expire(r)

Spec == Init /\ [][Next]_vars

THEOREM Spec => [](TypeOK /\ NoOverspend /\ SafetyInvariant)
=============================================================================
