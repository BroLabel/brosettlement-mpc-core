package shares

type ShareMeta struct {
	Algorithm        string
	Curve            string
	Version          uint32
	ChainCodePresent bool
	PublicKeyFormat  string
	DerivationScheme string
}
