package v4

// head key, case insensitive
const (
	headKeyData          = "date"
	headKeyXAmzDate      = "x-amz-date"
	headKeyAuthorization = "authorization"
	headKeyHost          = "host"
)

// url query params
const (
	queryKeySignature        = "X-Amz-Signature"
	queryKeyAlgorithm        = "X-Amz-Algorithm"
	queryKeyCredential       = "X-Amz-Credential"
	queryKeyDate             = "X-Amz-Date"
	queryKeySignatureHeaders = "X-Amz-SignedHeaders"
)

const (
	aws4HmacSha256Algorithm = "AWS4-HMAC-SHA256"
)
