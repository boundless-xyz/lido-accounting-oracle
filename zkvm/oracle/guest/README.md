# Balance and Exits Proof

This program consumes a membership bitfield and proof, and verifies the total balance of all non-exited validators as of the given block root.

It does this by verifying that:

- The given state root is contained in the given block root
- The membership bitfield is correct for the state root up to the total number of validators in the state
- The sum of all non-exited validators equals the given clBalance value
- The numValidators value equals the number of 1 bits in the membership bitfield
- The numExitedValidators value equals the number member validators where the exit epoch is set to less than the current epoch


