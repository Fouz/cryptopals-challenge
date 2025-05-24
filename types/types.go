package types

type Set[T comparable] map[T]struct{}

func NewSet[T comparable]() Set[T] {
	return make(Set[T])
}

func (s Set[T]) Contains(item T) bool {
	_, ok := s[item]
	return ok
}
