# Prover & Verifier Files

| File      | Use                                                   |
| --------- | ----------------------------------------------------- |
| `main.go` | gnark usage                                           |
| `try1.go` | preimage knowledge of a Poseidon hash                 |
| `try2.go` | multiple preimage knowledge of a single Poseidon hash |
| `try3.go` | MiMC hash                                             |

# Circuit Files

| File          | Circuit for                     |
| ------------- | ------------------------------- |
| `circuits.go` | `try1.go`, `try2.go`, `try3.go` |

# Footnotes

- Almost all packages used here uses `consensys/gnark-crypto` to get access to bn254-specific implementations
