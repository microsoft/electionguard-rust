# ElectionGuard 2.1 - Reference Implementation in Rust - Code Organization

## Election Data Objects

### Election Parameters

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR
  class ElectionParameters {
    FixedParameters
    VaryingParameters
  }
  ElectionParameters -- FixedParameters
  ElectionParameters -- VaryingParameters

  class FixedParameters {
    ElectionGuardDesignSpecificationVersion
    FixedParameterGenerationParameters
    Field p
    Group q
  }
  
  class VaryingParameters {
    N integer 1.. : Number of guardians
    K integer 1..N : Quorum threshold
    String info : Jurisdictional info, e.g. location
    String date : Optional, can be empty
    BallotChaining
  }

  VaryingParameters -- BallotChaining
  class BallotChaining{
    <<Enumeration>>
    Prohibited
    Allowed
    Required
  }
```

### Election Manifest

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class ElectionManifest {
    Vec1~Contest~
    Vec1~BallotStyle~
    VotingDeviceInformationSpec
  }
  ElectionManifest -- "0..*" Contest
  ElectionManifest -- "0..*" BallotStyle
  ElectionManifest -- VotingDeviceInformationSpec

  class Contest {
    ContestIndex
    String label
    ContestSelectionLimit
    Vec1~ContestOption~
  }
  Contest <-- "0..*" ContestOption

  class ContestOption {
    ContestIndex
    ContestOptionIndex
    String label
    OptionSelectionLimit
  }

  class BallotStyle {
    BallotStyleIndex
  }

  class VotingDeviceInformationSpec
```

### Guardian Keys

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR
  class GuardianKeyPurpose{
    <<Enumeration>>
    Encrypt_Ballot_NumericalVotesAndAdditionalDataFields
    Encrypt_Ballot_AdditionalFreeFormData
    Encrypt_InterGuardianCommunication
  }
  class AsymmetricKeyPart{
    <<Enumeration>>
    Public
    Secret
  }
  GuardianKeyId -- GuardianIndex
  GuardianKeyId -- GuardianKeyPurpose
  GuardianKeyId -- AsymmetricKeyPart
  class GuardianKeyId{
    GuardianIndex
    GuardianKeyPurpose
    AsymmetricKeyPart
  }
```

### Joint Public Keys

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction BT

  note "Only for GuardianKeyPurposes of **Encrypt_Ballot_NumericalVotesAndAdditionalDataFields** and
  **Encrypt_Ballot_AdditionalFreeFormData**. Not for **Encrypt_InterGuardianCommunication**."
  class JointPublicKey{
    GuardianKeyPurpose
    GroupElement
  }
```

### Pre-Voting Data

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class PreVotingData {
    ElectionParameters
    Hashes
    JointPublicKey k
    JointPublicKey k_hat
    HashesExt
  }
  PreVotingData -- ElectionParameters
  PreVotingData -- Hashes
  PreVotingData -- "2" JointPublicKey : K, ̂K (K hat)
  PreVotingData -- HashesExt

  class Hashes {
    HValue h_p
    HValue h_b
  }

  class JointPublicKey{
    GuardianKeyPurpose
    GroupElement
  }

  class HashesExt {
    HValue h_e
  }
```

### Voter Selections (plaintext)

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR
  class VoterSelectionsPlaintext {
    HValue h_e : Extended base hash of specific election
    Map~ContestIndex, ContestOptionFieldsPlaintexts~ contests_option_fields_plaintexts
  }
```

### Ballot (encrypted)

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR
  class Ballot{
    BallotStyleIndex : Ballot style
    BallotState : Ballot state
    HValue id_b : Selection encryption identifier '*id_B*'
    HValue h_i : Selection identifier hash *H_I*
    BTreeMap~ContestIndex, ContestDataFieldsCiphertexts~
    HValue confirmation_code
    String device_id
    String ballot_id
    String encryption_datetime : Optional, can be empty.
  }
  Ballot -- BallotState
  Ballot -- ContestDataFieldsCiphertexts

  class BallotState{
    <<Enumeration>>
    VoterSelectionsEncrypted
    Cast
    Spoiled
    Challenged
    ChallengedDecrypted
  }

  class ContestDataFieldsCiphertexts{
    Vec1~Ciphertext~ : Selectable options and data fields
  }
  ContestDataFieldsCiphertexts -- Ciphertext

  class Ciphertext{
    GroupElement alpha
    GroupElement beta
  }

```

### Pre-Decryption Election Record

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class PreDecryptionElectionRecord{
    PreVotingData
    Vec1~GuardianPublicKey~ : The guardian public keys
    Vec~Ballot~ : "All ballots whether cast, spoiled, or challenged
    TalliesEncrypted
  }
  PreDecryptionElectionRecord -- PreVotingData
  PreDecryptionElectionRecord -- TalliesEncrypted
```

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class TalliesEncrypted{
    Vec1~ContestDataFieldsTalliesCiphertexts~ : Each contest
  }
  TalliesEncrypted -- ContestDataFieldsTalliesCiphertexts

  class ContestDataFieldsTalliesCiphertexts{
    Vec1~ContestDataFieldTallyCiphertext~ : Each selectable option or additional data field
  }
  ContestDataFieldsTalliesCiphertexts -- Ciphertext
```

### Post-Decryption Election Record

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class ElectionRecord{
    PreDecryptionElectionRecord
    VerifiableTallies
  }
  ElectionRecord -- PreDecryptionElectionRecord
  ElectionRecord -- VerifiableTallies
```

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
  direction LR

  class VerifiableTallies{
    Vec1~ContestDataFieldsVerifiableTallies~ : Each contest
  }
  VerifiableTallies -- ContestDataFieldsVerifiableTallies

  class ContestDataFieldsVerifiableTallies{
    Vec1~VerifiableTally~ : Each selectable option or additional data field
  }
  ContestDataFieldsVerifiableTallies -- VerifiableTally

  class VerifiableTally{
    FieldElement tally_value : t in section 3.6.2
    FieldElement DecryptionProof.challenge
    FieldElement DecryptionProof.response
  }
```
