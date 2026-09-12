-------------------------- MODULE EventHorizon --------------------------
EXTENDS Naturals, FiniteSets

CONSTANT Authority

VARIABLES proposal, compiled, signed, attested, guardian, behavioral, decay,
          decayUpper, capState, committedEffects, attestationValid,
          trustDowngraded, signedTask, currentTask, signedWorkload,
          currentWorkload, isCanary, securityEvents, crashed, everConsumed,
          effectAmbiguous, denialState

vars == <<proposal, compiled, signed, attested, guardian, behavioral, decay,
          decayUpper, capState, committedEffects, attestationValid,
          trustDowngraded, signedTask, currentTask, signedWorkload,
          currentWorkload, isCanary, securityEvents, crashed, everConsumed,
          effectAmbiguous, denialState>>

Effective == compiled \cap signed \cap attested \cap guardian \cap behavioral \cap decay

CanRedeem ==
    capState = "issued"
    /\ ~crashed
    /\ attestationValid
    /\ ~trustDowngraded
    /\ signedTask = currentTask
    /\ signedWorkload = currentWorkload
    /\ ~isCanary
    /\ Effective # {}

Init ==
    /\ proposal = {}
    /\ compiled = {}
    /\ signed = {}
    /\ attested = Authority
    /\ guardian = {}
    /\ behavioral = {}
    /\ decay = Authority
    /\ decayUpper = Authority
    /\ capState = "none"
    /\ committedEffects = 0
    /\ attestationValid = FALSE
    /\ trustDowngraded = FALSE
    /\ signedTask = "none"
    /\ currentTask = "task-a"
    /\ signedWorkload = "none"
    /\ currentWorkload = "workload-a"
    /\ isCanary = FALSE
    /\ securityEvents = {}
    /\ crashed = FALSE
    /\ everConsumed = FALSE
    /\ effectAmbiguous = FALSE
    /\ denialState = "none"

Propose ==
    \E p \in SUBSET Authority:
        /\ proposal' = p
        /\ UNCHANGED <<compiled, signed, attested, guardian, behavioral, decay,
                        decayUpper, capState, committedEffects, attestationValid,
                        trustDowngraded, signedTask, currentTask, signedWorkload,
                        currentWorkload, isCanary, securityEvents, crashed,
                        everConsumed, effectAmbiguous, denialState>>

Compile ==
    /\ capState = "none"
    /\ compiled' = proposal \cap Authority
    /\ UNCHANGED <<proposal, signed, attested, guardian, behavioral, decay,
                    decayUpper, capState, committedEffects, attestationValid,
                    trustDowngraded, signedTask, currentTask, signedWorkload,
                    currentWorkload, isCanary, securityEvents, crashed,
                    everConsumed, effectAmbiguous, denialState>>

Attest ==
    \E a \in SUBSET Authority, valid \in BOOLEAN:
        /\ attested' = IF valid THEN a ELSE {}
        /\ attestationValid' = valid
        /\ UNCHANGED <<proposal, compiled, signed, guardian, behavioral, decay,
                        decayUpper, capState, committedEffects, trustDowngraded,
                        signedTask, currentTask, signedWorkload, currentWorkload,
                        isCanary, securityEvents, crashed, everConsumed,
                        effectAmbiguous, denialState>>

Issue ==
    /\ capState \in {"none", "expired", "revoked"}
    /\ attestationValid
    /\ compiled # {}
    /\ capState' = "issued"
    /\ signed' = compiled
    /\ guardian' = compiled
    /\ behavioral' = compiled
    /\ decay' = compiled
    /\ decayUpper' = compiled
    /\ signedTask' = currentTask
    /\ signedWorkload' = currentWorkload
    /\ isCanary' = FALSE
    /\ effectAmbiguous' = FALSE
    /\ denialState' = "none"
    /\ UNCHANGED <<proposal, compiled, attested, committedEffects,
                    attestationValid, trustDowngraded, currentTask,
                    currentWorkload, securityEvents, crashed, everConsumed>>

GuardianReduce ==
    \E permitted \in SUBSET Authority:
        /\ guardian' = guardian \cap permitted
        /\ UNCHANGED <<proposal, compiled, signed, attested, behavioral, decay,
                        decayUpper, capState, committedEffects, attestationValid,
                        trustDowngraded, signedTask, currentTask, signedWorkload,
                        currentWorkload, isCanary, securityEvents, crashed,
                        everConsumed, effectAmbiguous, denialState>>

BehavioralReduce ==
    \E permitted \in SUBSET Authority:
        /\ behavioral' = behavioral \cap permitted
        /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, decay,
                        decayUpper, capState, committedEffects, attestationValid,
                        trustDowngraded, signedTask, currentTask, signedWorkload,
                        currentWorkload, isCanary, securityEvents, crashed,
                        everConsumed, effectAmbiguous, denialState>>

DecayStep ==
    \E permitted \in SUBSET Authority:
        /\ decayUpper' = decay
        /\ decay' = decay \cap permitted
        /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                        capState, committedEffects, attestationValid,
                        trustDowngraded, signedTask, currentTask, signedWorkload,
                        currentWorkload, isCanary, securityEvents, crashed,
                        everConsumed, effectAmbiguous, denialState>>

TrustDowngrade ==
    /\ trustDowngraded' = TRUE
    /\ attested' = {}
    /\ UNCHANGED <<proposal, compiled, signed, guardian, behavioral, decay,
                    decayUpper, capState, committedEffects, attestationValid,
                    signedTask, currentTask, signedWorkload, currentWorkload,
                    isCanary, securityEvents, crashed, everConsumed,
                    effectAmbiguous, denialState>>

ChangeBinding ==
    /\ currentTask' = IF currentTask = "task-a" THEN "task-b" ELSE "task-a"
    /\ currentWorkload' = IF currentWorkload = "workload-a" THEN "workload-b" ELSE "workload-a"
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, capState, committedEffects,
                    attestationValid, trustDowngraded, signedTask,
                    signedWorkload, isCanary, securityEvents, crashed,
                    everConsumed, effectAmbiguous, denialState>>

Redeem ==
    /\ CanRedeem
    /\ capState' = "consumed"
    /\ committedEffects' = committedEffects + 1
    /\ everConsumed' = TRUE
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, attestationValid, trustDowngraded,
                    signedTask, currentTask, signedWorkload, currentWorkload,
                    isCanary, securityEvents, crashed, effectAmbiguous,
                    denialState>>

Expire ==
    /\ capState = "issued"
    /\ capState' = "expired"
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, committedEffects, attestationValid,
                    trustDowngraded, signedTask, currentTask, signedWorkload,
                    currentWorkload, isCanary, securityEvents, crashed,
                    everConsumed, effectAmbiguous, denialState>>

Revoke ==
    /\ capState = "issued"
    /\ capState' = "revoked"
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, committedEffects, attestationValid,
                    trustDowngraded, signedTask, currentTask, signedWorkload,
                    currentWorkload, isCanary, securityEvents, crashed,
                    everConsumed, effectAmbiguous, denialState>>

SeedCanary ==
    /\ capState \in {"none", "expired", "revoked"}
    /\ capState' = "canary"
    /\ isCanary' = TRUE
    /\ signed' = {}
    /\ UNCHANGED <<proposal, compiled, attested, guardian, behavioral, decay,
                    decayUpper, committedEffects, attestationValid,
                    trustDowngraded, signedTask, currentTask, signedWorkload,
                    currentWorkload, securityEvents, crashed, everConsumed,
                    effectAmbiguous, denialState>>

CanaryAttempt ==
    /\ capState = "canary"
    /\ securityEvents' = securityEvents \cup {"canary-attempt"}
    /\ denialState' = "known-no-effect"
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, capState, committedEffects,
                    attestationValid, trustDowngraded, signedTask, currentTask,
                    signedWorkload, currentWorkload, isCanary, crashed,
                    everConsumed, effectAmbiguous>>

Crash ==
    /\ crashed' = TRUE
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, capState, committedEffects,
                    attestationValid, trustDowngraded, signedTask, currentTask,
                    signedWorkload, currentWorkload, isCanary, securityEvents,
                    everConsumed, effectAmbiguous, denialState>>

Recover ==
    /\ crashed
    /\ crashed' = FALSE
    /\ capState' = IF everConsumed THEN "consumed" ELSE capState
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, committedEffects, attestationValid,
                    trustDowngraded, signedTask, currentTask, signedWorkload,
                    currentWorkload, isCanary, securityEvents, everConsumed,
                    effectAmbiguous, denialState>>

AmbiguousOutcome ==
    /\ capState = "consumed"
    /\ effectAmbiguous' = TRUE
    /\ denialState' = "ambiguous"
    /\ UNCHANGED <<proposal, compiled, signed, attested, guardian, behavioral,
                    decay, decayUpper, capState, committedEffects,
                    attestationValid, trustDowngraded, signedTask, currentTask,
                    signedWorkload, currentWorkload, isCanary, securityEvents,
                    crashed, everConsumed>>

Next == Propose \/ Compile \/ Attest \/ Issue \/ GuardianReduce
        \/ BehavioralReduce \/ DecayStep \/ TrustDowngrade \/ ChangeBinding
        \/ Redeem \/ Expire \/ Revoke \/ SeedCanary \/ CanaryAttempt
        \/ Crash \/ Recover \/ AmbiguousOutcome

Spec == Init /\ [][Next]_vars

AtMostOneCommittedEffect == committedEffects <= 1
ConsumedCapabilityCannotRedeem == capState = "consumed" => ~CanRedeem
GuardianNeverAddsAuthority == guardian \subseteq compiled
BehavioralGuardianNeverAddsAuthority == behavioral \subseteq compiled
SynthesizerCannotGrantAuthority == compiled \subseteq Authority
CompiledCeilingNeverExceedsGlobalMaximum == compiled \subseteq Authority
EffectiveAuthorityNeverExceedsCompiledCeiling == Effective \subseteq compiled
EffectiveAuthorityNeverExceedsSignedAuthority == Effective \subseteq signed
EffectiveAuthorityNeverExceedsAttestedAuthority == Effective \subseteq attested
EffectiveAuthorityNeverExceedsPolicyAuthority == Effective \subseteq Authority
DecayIsMonotonic == decay \subseteq decayUpper
TrustDowngradePreventsRestrictedRedemption == trustDowngraded => ~CanRedeem
InvalidAttestationCannotAuthorize == ~attestationValid => ~CanRedeem
CrashRecoveryCannotRestoreConsumedCapability == everConsumed => capState # "issued"
AmbiguousRetryCannotCreateDuplicateEffect == effectAmbiguous => committedEffects <= 1
CapabilityIsBoundToTaskAndWorkload == CanRedeem => (signedTask = currentTask /\ signedWorkload = currentWorkload)
ExpiredCapabilityCannotCommitEffect == capState = "expired" => ~CanRedeem
CanaryCannotCommitEffect == isCanary => ~CanRedeem
CanaryAttemptProducesSecurityEvent == denialState = "known-no-effect" => "canary-attempt" \in securityEvents
DenialCertificateCannotClaimKnownNoEffectWhenStateIsAmbiguous == effectAmbiguous => denialState # "known-no-effect"

=============================================================================
