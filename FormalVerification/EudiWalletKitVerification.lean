/-
  Copyright (c) 2026 European Commission
  Licensed under the Apache License, Version 2.0.

  A Lean 4 model of security-critical, pure issuance decisions.  This is not a
  claim that Lean type-checks Swift.  The traceability document identifies the
  Swift implementation points and tests that must remain equivalent to this
  model.
-/

import Std

namespace EudiWalletKitVerification

/-! ## Credential batch bounds

Mirrors `OpenId4VciService.validateBatchSize`.
-/

def ValidBatchSize (size : Nat) : Prop := 1 ≤ size ∧ size ≤ 100

def acceptsBatchSize (size : Nat) : Bool :=
  decide (1 ≤ size) && decide (size ≤ 100)

theorem accepted_batch_size_is_valid {size : Nat}
    (accepted : acceptsBatchSize size = true) : ValidBatchSize size := by
  simp [acceptsBatchSize] at accepted
  exact accepted

theorem valid_batch_size_is_accepted {size : Nat}
    (valid : ValidBatchSize size) : acceptsBatchSize size = true := by
  simp [acceptsBatchSize, valid.1, valid.2]

theorem zero_batch_is_rejected : acceptsBatchSize 0 = false := by
  decide

theorem oversized_batch_is_rejected : acceptsBatchSize 101 = false := by
  decide

/-! ## OAuth authorization response state binding

Mirrors `OpenId4VciService.validateAuthorizationState`.  A successful result
can only return the expected state; a missing or unequal state is rejected.
-/

def authorizeState (expected : String) : Option String → Option String
  | none => none
  | some received => if received == expected then some received else none

theorem authorized_state_matches_expected {expected received accepted : String}
    (success : authorizeState expected (some received) = some accepted) :
    accepted = expected := by
  simp [authorizeState] at success
  exact success.2.symm.trans success.1

theorem missing_state_is_rejected (expected : String) :
    authorizeState expected none = none := by
  rfl

theorem unequal_state_is_rejected {expected received : String}
    (different : received ≠ expected) :
    authorizeState expected (some received) = none := by
  simp [authorizeState, different]

/-! ## Credential/public-key response pairing

Mirrors the count check followed by `zip` in
`OpenId4VciService.pairCredentialPayloadsWithPublicKeys`.
-/

def pairResponses {Credential Key : Type} (credentials : List Credential)
    (keys : List Key) : Option (List (Credential × Key)) :=
  if credentials.length = keys.length then some (List.zip credentials keys) else none

theorem successful_pairing_has_equal_input_counts {Credential Key : Type}
    {credentials : List Credential} {keys : List Key} {pairs : List (Credential × Key)}
    (success : pairResponses credentials keys = some pairs) :
    credentials.length = keys.length := by
  simp [pairResponses] at success
  exact success.1

theorem unequal_input_counts_are_rejected {Credential Key : Type}
    {credentials : List Credential} {keys : List Key}
    (different : credentials.length ≠ keys.length) :
    pairResponses credentials keys = none := by
  simp [pairResponses, different]

theorem successful_pairing_preserves_cardinality {Credential Key : Type}
    {credentials : List Credential} {keys : List Key} {pairs : List (Credential × Key)}
    (success : pairResponses credentials keys = some pairs) :
    pairs.length = keys.length := by
  simp [pairResponses] at success
  calc
    pairs.length = (credentials.zip keys).length := by rw [success.2]
    _ = keys.length := by simp [success.1]

/-! ## One active resume lease per document

Mirrors the set-membership decision in `IssuanceResumeLeaseRegistry.acquire`.
The production registry additionally scopes this key by its storage identity.
-/

def acquireLease (active : List String) (documentId : String) : Option (List String) :=
  if documentId ∈ active then none else some (documentId :: active)

theorem successful_lease_was_not_already_active {active next : List String}
    {documentId : String} (success : acquireLease active documentId = some next) :
    documentId ∉ active := by
  simp [acquireLease] at success
  exact success.1

theorem active_lease_cannot_be_acquired_twice {active : List String}
    {documentId : String} (present : documentId ∈ active) :
    acquireLease active documentId = none := by
  simp [acquireLease, present]

theorem releasing_a_new_lease_restores_the_prior_set {active : List String}
    {documentId : String} :
    (documentId :: active).erase documentId = active := by
  simp

end EudiWalletKitVerification
