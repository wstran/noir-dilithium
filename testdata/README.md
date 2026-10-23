# Test vectors

| File | Source |
| --- | --- |
| `kat_dilithium3_r3.json` | Known-answer tests of the pq-crystals Dilithium reference implementation at tag v3.1 (CC0), `PQCsignKAT_Dilithium3.rsp` with sha256 `8196b32212753f525346201ffec1c7a0a852596fa0b57bd4e2746231dab44d55`, rebuilt by `scripts/build_kat_r3.sh` and converted to JSON by `scripts/fetch_vectors.py`. |
| `acvp_mldsa65_sigver.json` | NIST ACVP-Server, see below. |
| `edge_vectors.json` | Valid signatures generated with dilithium-py 1.5.1 by `scripts/make_edge_vectors.py` from fixed seeds (key generation from 48 zero bytes for round 3, `key_derive` on 32 zero bytes for ML-DSA-65, deterministic signing, counter messages) that reach an empty and a 255-byte context, an empty hint polynomial and 55 hints. |
| `prepared_keys.json` | tr (32 and 64 bytes), A_hat and NTT(t1 * 2^13) for the public keys of KAT vectors 0 to 5, computed with dilithium-py 1.5.1 by `scripts/fetch_vectors.py --prepared`. |

Every vector was cross-checked with dilithium-py 1.5.1 when these files were built.

## NIST ACVP-Server vectors

`acvp_mldsa65_sigver.json` is derived from `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`
of the NIST ACVP-Server repository (https://github.com/usnistgov/ACVP-Server), commit `a7f283cd`, file sha256
`47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`. The National Institute of Standards and
Technology is the source of these test vectors.

Changes, October 2026: only the ML-DSA-65 test groups of the pure, internal and external-mu interfaces were kept
(the pre-hash groups were dropped), and the cases were reformatted into this file's JSON layout.

The ACVP-Server license notice, kept intact as it requires:

> NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the
> software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create
> derivative works of the software or any portion of the software, and you may copy and distribute such
> modifications or works. Modified works should carry a notice stating that you changed the software and should
> note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards
> and Technology as the source of the software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN
> FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT
> THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST
> DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING
> BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and distributing the software and you
> assume all risks associated with its use, including but not limited to the risks and costs of program errors,
> compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or
> interruption of operation. This software is not intended to be used in any situation where a failure could
> cause risk of injury or damage to property. The software developed by NIST employees is not subject to
> copyright protection within the United States.
