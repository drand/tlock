# age-plugin-tlock is a tlock plugin for `age`

This binary is meant to be put in your PATH so that `age` can rely on it when it encounters either a `age1tlock1` recipient or a `AGE-PLUGIN-TLOCK` identity.

It allows 3 different types of recipients and identities:
- the static ones, where you're providing all informations such as public key, chainshash, genesis time, period, round value and even signature (for decryption)
- the remote endpoint ones, where you specify which remote endpoint you'd like to rely on and which chainhash you're targeting
- the interactive one where `age` will be prompting you for all necessary informations

# tlock Identities

