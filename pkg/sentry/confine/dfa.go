// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package confine

import (
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/sync"
)

// A profile's rules are compiled into one deterministic finite automaton over
// the bytes of a path, which is how AppArmor itself evaluates policy: the cost
// of a check is the length of the path and does not depend on how many rules
// the profile has. Walking the rules one at a time meant every file access
// scanned hundreds of patterns.
//
// Bytes are grouped into equivalence classes first. Every byte that appears in
// a pattern as a literal or inside a character class gets its own class, '/'
// gets its own because '*' and '?' do not cross it, and every remaining byte
// shares one. Each pattern's predicates are then constant across a class, and a
// state's transition table has one entry per class rather than 256.

// maxDFAStates bounds the states cached for one profile. A real profile of
// 1500 rules compiles to about 20000 states in full, which costs seconds and
// several megabytes; a workload touches a small fraction of them, so states are
// built as paths reach them and this is only a ceiling.
const maxDFAStates = 65536

// deadState is the state entered when no pattern can match the path any more.
const deadState = 0

// unknownState marks a transition that has not been computed yet.
const unknownState = -1

// itemKind is what one element of a compiled pattern matches.
type itemKind uint8

const (
	// itemLit matches one specific byte.
	itemLit itemKind = iota

	// itemAnyNonSlash matches any byte except '/', from '?'.
	itemAnyNonSlash

	// itemStarNonSlash matches zero or more bytes except '/', from '*'.
	itemStarNonSlash

	// itemStarAny matches zero or more of any byte, from '**'.
	itemStarAny

	// itemClass matches any byte in a set, from '[...]'.
	itemClass
)

// item is one element of a compiled pattern.
type item struct {
	kind itemKind

	// b is the byte itemLit matches.
	b byte

	// set is the resolved membership of an itemClass, negation applied.
	set *[256]bool
}

// accept is the permissions a set of matching rules grants or denies.
//
// +stateify savable
type accept struct {
	// allowAny is granted to any task.
	allowAny Perm

	// allowOwner is granted only to a task that owns the file.
	allowOwner Perm

	// deny is refused regardless of what is granted.
	deny Perm
}

// dfa is a profile compiled into an automaton over the bytes of a path. States
// are built the first time a path reaches them and kept, so the cost is paid by
// the paths a workload actually uses rather than at policy load.
//
// +stateify savable
type dfa struct {
	// mu guards every field below it.
	mu sync.RWMutex `state:"nosave"`

	// bld is the scratch state of subset construction, kept for as long as
	// states may still be built.
	// +checklocks:mu
	bld *builder

	// rules are the profile's rules, needed to work out what a new state
	// accepts.
	// +checklocks:mu
	rules []Rule

	// sets holds the positions each state stands for.
	// +checklocks:mu
	sets [][]int32

	// ids maps a position set to the state that stands for it.
	// +checklocks:mu
	ids map[string]int32

	// full is set once the state ceiling is reached, after which the
	// profile is matched rule by rule instead.
	// +checklocks:mu
	full bool

	// classOf maps a byte to its equivalence class. It is uint16 because a
	// profile could in principle distinguish all 256 byte values, which a
	// uint8 count cannot represent.
	classOf [256]uint16

	// numClasses is the number of equivalence classes.
	numClasses int

	// trans is the transition table, indexed by state*numClasses + class.
	trans []int32

	// accepts is the permissions each state accepts, indexed by state.
	accepts []accept

	// classByte is one byte belonging to each class, used while compiling.
	classByte []byte
}

// compile prepares a profile for matching. It builds only the start state; the
// rest are built as paths reach them.
func compile(name string, rules []Rule) *dfa {
	items, ok := compileItems(rules)
	if !ok {
		return nil
	}

	d := &dfa{rules: rules}
	d.buildClasses(items)

	// Positions are numbered per pattern: base[p]+i is item i of pattern p,
	// and base[p]+len(items[p]) is the position that accepts it.
	base := make([]int32, len(items)+1)
	for p := range items {
		base[p+1] = base[p] + int32(len(items[p])) + 1
	}
	d.bld = newBuilder(items, base)
	d.bld.begin()
	for p := range items {
		d.bld.add(base[p])
	}
	start := d.bld.closure()

	// State 0 is the dead state, so that reaching it means no pattern can
	// match. State 1 is the start.
	d.trans = make([]int32, 2*d.numClasses)
	for i := range d.trans {
		d.trans[i] = unknownState
	}
	for class := 0; class < d.numClasses; class++ {
		d.trans[class] = deadState
	}
	d.accepts = make([]accept, 2)
	d.accepts[1] = d.bld.acceptOf(rules, start)
	d.sets = [][]int32{nil, start}
	d.ids = map[string]int32{key(start): 1}
	return d
}

// transition returns the state reached from state on a byte of the given class,
// building it if this is the first time it is needed.
//
// Preconditions: d.mu must be locked.
// +checklocks:d.mu
func (d *dfa) transition(state int32, class int) int32 {
	if t := d.trans[int(state)*d.numClasses+class]; t != unknownState {
		return t
	}
	next := d.bld.step(d.sets[state], d.classByte[class])
	id := int32(deadState)
	if len(next) != 0 {
		k := key(next)
		var ok bool
		if id, ok = d.ids[k]; !ok {
			if len(d.sets) >= maxDFAStates {
				d.full = true
				return unknownState
			}
			id = int32(len(d.sets))
			d.ids[k] = id
			d.sets = append(d.sets, next)
			d.accepts = append(d.accepts, d.bld.acceptOf(d.rules, next))
			d.trans = append(d.trans, make([]int32, d.numClasses)...)
			for i := int(id) * d.numClasses; i < len(d.trans); i++ {
				d.trans[i] = unknownState
			}
		}
	}
	d.trans[int(state)*d.numClasses+class] = id
	return id
}

// compileItems converts each rule's pattern into items. It reports false if any
// pattern cannot be compiled, in which case the profile is matched rule by
// rule.
func compileItems(rules []Rule) ([][]item, bool) {
	out := make([][]item, 0, len(rules))
	for i := range rules {
		its, ok := patternItems(rules[i].Pattern)
		if !ok {
			return nil, false
		}
		out = append(out, its)
	}
	return out, true
}

// patternItems compiles one pattern. Brace alternations are expanded before a
// rule is stored, so a pattern that still contains one is not compiled.
func patternItems(pattern string) ([]item, bool) {
	var out []item
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '{', '}':
			return nil, false
		case '?':
			out = append(out, item{kind: itemAnyNonSlash})
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				out = append(out, item{kind: itemStarAny})
				continue
			}
			out = append(out, item{kind: itemStarNonSlash})
		case '[':
			end := strings.IndexByte(pattern[i:], ']')
			if end < 0 {
				// An unmatched bracket matches literally.
				out = append(out, item{kind: itemLit, b: c})
				continue
			}
			end += i
			set := new([256]bool)
			body := pattern[i+1 : end]
			negate := false
			if len(body) != 0 && (body[0] == '^' || body[0] == '!') {
				negate = true
				body = body[1:]
			}
			for j := 0; j < len(body); j++ {
				if j+2 < len(body) && body[j+1] == '-' {
					for b := int(body[j]); b <= int(body[j+2]); b++ {
						set[b] = true
					}
					j += 2
					continue
				}
				set[body[j]] = true
			}
			if negate {
				for b := range set {
					set[b] = !set[b]
				}
				// A negated class does not match '/', as in
				// AppArmor: a class never spans a component.
				set['/'] = false
			}
			out = append(out, item{kind: itemClass, set: set})
			i = end
		default:
			out = append(out, item{kind: itemLit, b: c})
		}
	}
	return out, true
}

// buildClasses partitions the 256 byte values so that every predicate any
// pattern applies is constant within a class. It starts with one class holding
// every byte and refines it by each predicate: the byte a literal matches, the
// membership of each character class, and '/' on its own, since '*' and '?' do
// not cross it. The result is the coarsest such partition, which keeps a state's
// transition row far shorter than 256. Assigning every mentioned byte its own
// class instead overflowed to 256 classes as soon as a profile used a negated
// class such as [^1-9], which mentions almost every byte.
func (d *dfa) buildClasses(items [][]item) {
	var classOf [256]uint16
	next := uint16(1)
	refine := func(set *[256]bool) {
		// Split each existing class into its members and non-members.
		remap := make(map[uint32]uint16)
		var out [256]uint16
		for b := 0; b < 256; b++ {
			key := uint32(classOf[b]) << 1
			if set[b] {
				key |= 1
			}
			id, ok := remap[key]
			if !ok {
				id = next
				next++
				remap[key] = id
			}
			out[b] = id
		}
		classOf = out
	}

	slash := new([256]bool)
	slash['/'] = true
	refine(slash)

	var litSeen [256]bool
	for _, its := range items {
		for _, it := range its {
			switch it.kind {
			case itemLit:
				if litSeen[it.b] {
					continue
				}
				litSeen[it.b] = true
				set := new([256]bool)
				set[it.b] = true
				refine(set)
			case itemClass:
				refine(it.set)
			}
		}
	}

	// Renumber to a dense range so the transition table has no gaps.
	dense := make(map[uint16]uint16, 256)
	for b := 0; b < 256; b++ {
		id, ok := dense[classOf[b]]
		if !ok {
			id = uint16(len(dense))
			dense[classOf[b]] = id
		}
		d.classOf[b] = id
	}
	d.numClasses = len(dense)
	d.classByte = make([]byte, d.numClasses)
	var filled [256]bool
	for b := 0; b < 256; b++ {
		if c := d.classOf[b]; !filled[c] {
			filled[c] = true
			d.classByte[c] = byte(b)
		}
	}
}

// builder holds the scratch state of subset construction. Membership is tested
// through a generation-stamped array rather than by scanning the set, which
// turned construction of a real profile from tens of seconds into well under
// one.
type builder struct {
	items [][]item
	base  []int32

	// patOf maps a position to the pattern it belongs to, so that splitting
	// a position is a lookup rather than a binary search.
	patOf []int32

	// mark stamps a position with the generation that last added it.
	mark []int32
	gen  int32

	// scratch is the set being built.
	scratch []int32
}

func newBuilder(items [][]item, base []int32) *builder {
	n := base[len(base)-1]
	b := &builder{
		items: items,
		base:  base,
		patOf: make([]int32, n),
		mark:  make([]int32, n),
	}
	for p := range items {
		for pos := base[p]; pos < base[p+1]; pos++ {
			b.patOf[pos] = int32(p)
		}
	}
	return b
}

// begin starts a new set.
func (b *builder) begin() {
	b.gen++
	b.scratch = b.scratch[:0]
}

// add puts pos in the set if it is not already there.
func (b *builder) add(pos int32) bool {
	if b.mark[pos] == b.gen {
		return false
	}
	b.mark[pos] = b.gen
	b.scratch = append(b.scratch, pos)
	return true
}

// split returns the pattern a position belongs to and the index within it.
func (b *builder) split(pos int32) (int, int) {
	p := b.patOf[pos]
	return int(p), int(pos - b.base[p])
}

// closure adds the positions reachable without consuming a byte: a star may
// match nothing, so the position after it is reachable too. It must be called
// with the set already in scratch.
func (b *builder) closure() []int32 {
	for i := 0; i < len(b.scratch); i++ {
		pos := b.scratch[i]
		p, idx := b.split(pos)
		if idx >= len(b.items[p]) {
			continue
		}
		switch b.items[p][idx].kind {
		case itemStarNonSlash, itemStarAny:
			b.add(pos + 1)
		}
	}
	sort.Slice(b.scratch, func(i, j int) bool { return b.scratch[i] < b.scratch[j] })
	out := make([]int32, len(b.scratch))
	copy(out, b.scratch)
	return out
}

// step returns the positions reachable from set by consuming one byte of the
// given class.
func (b *builder) step(set []int32, c byte) []int32 {
	isSlash := c == '/'
	b.begin()
	for _, pos := range set {
		p, idx := b.split(pos)
		if idx >= len(b.items[p]) {
			continue
		}
		switch it := b.items[p][idx]; it.kind {
		case itemLit:
			if it.b == c {
				b.add(pos + 1)
			}
		case itemAnyNonSlash:
			if !isSlash {
				b.add(pos + 1)
			}
		case itemStarNonSlash:
			if !isSlash {
				b.add(pos)
			}
		case itemStarAny:
			b.add(pos)
		case itemClass:
			if it.set[c] {
				b.add(pos + 1)
			}
		}
	}
	if len(b.scratch) == 0 {
		return nil
	}
	return b.closure()
}

// acceptOf returns the permissions the rules accepted by a state grant.
func (b *builder) acceptOf(rules []Rule, set []int32) accept {
	var a accept
	for _, pos := range set {
		p, idx := b.split(pos)
		if idx != len(b.items[p]) {
			continue
		}
		r := &rules[p]
		switch {
		case r.Deny:
			a.deny |= r.Perms
		case r.Owner:
			a.allowOwner |= r.Perms
		default:
			a.allowAny |= r.Perms
		}
	}
	return a
}

// key serializes a position set so that equal sets map to one state. The bytes
// of the positions are used directly: formatting them as decimal was a
// measurable part of construction.
func key(set []int32) string {
	var b strings.Builder
	b.Grow(len(set) * 4)
	for _, pos := range set {
		b.WriteByte(byte(pos))
		b.WriteByte(byte(pos >> 8))
		b.WriteByte(byte(pos >> 16))
		b.WriteByte(byte(pos >> 24))
	}
	return b.String()
}

// match walks path through the automaton and returns what the rules matching it
// grant and deny. It reports false if the automaton cannot answer, in which case
// the caller matches the rules one at a time.
func (d *dfa) match(path string) (accept, bool) {
	// The walk needs no lock once every transition it uses has been built,
	// which is the steady state.
	d.mu.RLock()
	state, ok := d.walk(path)
	full := d.full
	if ok {
		a := d.accepts[state]
		d.mu.RUnlock()
		return a, true
	}
	d.mu.RUnlock()
	if full {
		return accept{}, false
	}

	// Some transition is missing; build what is needed.
	d.mu.Lock()
	defer d.mu.Unlock()
	state = 1
	for i := 0; i < len(path); i++ {
		state = d.transition(state, int(d.classOf[path[i]]))
		switch state {
		case deadState:
			return accept{}, true
		case unknownState:
			// The state ceiling was reached.
			return accept{}, false
		}
	}
	return d.accepts[state], true
}

// walk follows path as far as the states already built allow.
//
// Preconditions: d.mu must be locked for reading.
// +checklocksread:d.mu
func (d *dfa) walk(path string) (int32, bool) {
	state := int32(1)
	for i := 0; i < len(path); i++ {
		state = d.trans[int(state)*d.numClasses+int(d.classOf[path[i]])]
		switch state {
		case deadState:
			return 0, true
		case unknownState:
			return 0, false
		}
	}
	return state, true
}

// numStates returns how many states have been built.
func (d *dfa) numStates() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.sets)
}

// markFullForTest makes the automaton behave as though it had reached its state
// ceiling, with every transition unbuilt, so that a test can exercise the
// fallback to matching rules one at a time.
func (d *dfa) markFullForTest() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.full = true
	for i := range d.trans {
		d.trans[i] = unknownState
	}
}
