# 🛡️FDAAC-CR: Practical Delegatable Attribute-Based Anonymous Credentials with Fine-grained Delegation Management and Chainable Revocation

This repository provides the implementation of **FDAAC-CR**, a novel Delegatable Anonymous Credential (DAC) system with **fine-grained delegation management** and **chainable revocation**.

FDAAC-CR builds upon a new cryptographic primitive we propose: **Structure-Preserving Signatures on Equivalence Classes of Vector Commitments (SPSEQ-VC)**, enabling flexible and efficient anonymous credentials.


## 🔬 Our Contributions

- **SPSEQ-VC Primitive**: A structure-preserving signature with a message space over re-randomizable vector commitments. It allows fine-grained adaptation, position-binding, and subset openings, supporting adaption via update keys.
- **FDAAC-CR Scheme**:
  - Attribute-based credentials with selective disclosure
  - Fine-grained delegation control (attribute scope, delegation depth)
  - Efficient **chainable revocation** across delegation hierarchies
  - Practical performance: proof size is independent of total attributes
- **Evaluation**:
  - Benchmarks comparing FDAAC-CR, Practical DAC From SPSEQ (Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS23), and PS-DAC (How to Securely Delegate and Revoke Partial  Authorization Credentials, TDSC24)
  - Reproductions of relevant baseline re-implementations (`dac.py`, `ps_dac.py`)

## 📦 Installation


**Requirements**:
The following system requirements must be met in order to run the code:

- Linux operating system
- x86_64 architecture

Note that the software has only been tested on Linux/x86_64 and may not work on other platforms.

#  Getting started
Library is built on top of [petlib](https://github.com/gdanezis/petlib) and [bplib ](https://github.com/gdanezis/bplib). To install the development dependencies run the following commands inside the cloned repository:

1. Install nix with the required experimental features from determinate systems

           curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
    
2. Run: 
            
            nix develop

This will activate the development environment with the required dependencies.

# Run tests with nix

To run the tests in a precisely defined python environment using Nix 
         
         nix develop -c pytest -s -v tests/


## 🧪 Usage and Testing

Run the core tests:
```bash
pytest tests/
```

Run performance benchmarks:
```bash
python Benchmarks/test_time_xxx.py
```

## 📁 Project Structure

```
DAC-from-EQS-main-TIFS/
├── Benchmarks/
│   ├── test_time_acc.py
│   ├── test_time_dac.py            # DAC from SPSEQ-UC benchmark (PETS23)
│   ├── test_time_dac_cr.py         # FDAAC-CR benchmark
│   ├── test_time_ps_dac.py         # PS-DAC benchmark (TDSC24)
│   └── test_time_spseq_vc.py
│
├── core/
│   ├── Acc.py                      # Polynomial accumulator with revocation
│   ├── aSVC.py                     # Re-randomized vector commitment
│   ├── dac.py                      # PETS 2023 DAC baseline implementation
│   ├── dac_cr.py                   # Our FDAAC-CR full protocol
│   ├── ps_dac.py                   # PS-DAC protocol from TDSC 2024
│   ├── set_commit.py               # Set commitment helper
│   ├── spseq_uc.py                 # SPSEQ with update commitments
│   ├── spseq_vc.py                 # SPSEQ over VC (SPSEQ-VC)
│   ├── spseq_vc_pure.py            # Variant: pure VC SPSEQ
│   ├── util.py                     # Polynomial, randomness, and conversion utilities
│   └── zkp.py                      # Schnorr-style zero-knowledge proof system
│
├── tests/
│   ├── test_Acc.py                 # Accumulator test
│   ├── test_dac.py                 # DAC from SPSEQ-UC test
│   ├── test_dac_CR.py              # FDAAC-CR: issue, delegate, revoke, prove
│   ├── test_ps_dac.py              # PS-DAC test
│   ├── test_setcommit.py
│   ├── test_spseq_uc.py
│   ├── test_spseq_vc.py            # SPSEQ-VC test
│   ├── test_vectorcommit.py        # Re-randomized vector commitment test
│   └── test_zkp.py
│
├── requirements.txt
├── LICENSE
└── README.md
```

## ⚠️ Notes on Accumulator Witness Failures

The accumulator's `NonMemberProve()` may return `False` in randomized tests when:
- Randomly generated sets are **not disjoint**
- Polynomial evaluation yields `0 mod order`, making inverse undefined
- Malformed input formatting

We use `pytest.mark.flaky` to automatically retry under such uncertainty.

## 🧠 Example Usage
```python
from core.dac_cr import DAC

dac = DAC(t=30, l_message=10, max_blacklist=20)
pp_dac = dac.setup()
sk_ca, vk_ca = dac.ca_keygen(pp_dac)
usk, upk = dac.user_keygen(pp_dac)
nym, _, proof_nym = dac.nym_gen(pp_dac, usk, upk)

cred = dac.issue_cred(pp_dac, dac.acc_scheme.setup()[0], vk_ca,
                      attr_vector=[["age=18", "citizen=yes"]],
                      subset_indics={0: 0, 1: 1},
                      sk=sk_ca, nym_u=nym, k_prime=2, proof_nym_u=proof_nym)
```

# Acknowledgements

> Our code is inspired by prior works:
- [Practical Delegatable Anonymous Credentials From Equivalence Class Signatures (PETS 2023)](https://petsymposium.org/popets/2023/popets-2023-0093.pdf)
