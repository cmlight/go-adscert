package adscertcrypto

// InternalBaseKey provides a base interface internal to the API implementation
// and should not be used by API clients. This interface may use methods that
// deliberately encrypt or obfuscate key material, so API clients should not
// attempt to interpret these details.
type InternalBaseKey interface {
	InternalCopyInto(dest []byte)
}
