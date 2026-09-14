//go:build race

package mailparser

// raceEnabled reports whether the race detector, which inflates allocation
// counts, is active.
const raceEnabled = true
