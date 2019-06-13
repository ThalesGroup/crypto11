package crypto11

import (
	"fmt"
	"github.com/miekg/pkcs11"
)

type AttributeType uint

//noinspection GoUnusedConst
const (
	CkaClass                  = AttributeType(0x00000000)
	CkaToken                  = AttributeType(0x00000001)
	CkaPrivate                = AttributeType(0x00000002)
	CkaLabel                  = AttributeType(0x00000003)
	CkaApplication            = AttributeType(0x00000010)
	CkaValue                  = AttributeType(0x00000011)
	CkaObjectId               = AttributeType(0x00000012)
	CkaCertificateType        = AttributeType(0x00000080)
	CkaIssuer                 = AttributeType(0x00000081)
	CkaSerialNumber           = AttributeType(0x00000082)
	CkaAcIssuer               = AttributeType(0x00000083)
	CkaOwner                  = AttributeType(0x00000084)
	CkaAttrTypes              = AttributeType(0x00000085)
	CkaTrusted                = AttributeType(0x00000086)
	CkaCertificateCategory    = AttributeType(0x00000087)
	CkaJavaMidpSecurityDomain = AttributeType(0x00000088)
	CkaUrl                    = AttributeType(0x00000089)
	CkaHashOfSubjectPublicKey = AttributeType(0x0000008A)
	CkaHashOfIssuerPublicKey  = AttributeType(0x0000008B)
	CkaNameHashAlgorithm      = AttributeType(0x0000008C)
	CkaCheckValue             = AttributeType(0x00000090)

	CkaKeyType         = AttributeType(0x00000100)
	CkaSubject         = AttributeType(0x00000101)
	CkaId              = AttributeType(0x00000102)
	CkaSensitive       = AttributeType(0x00000103)
	CkaEncrypt         = AttributeType(0x00000104)
	CkaDecrypt         = AttributeType(0x00000105)
	CkaWrap            = AttributeType(0x00000106)
	CkaUnwrap          = AttributeType(0x00000107)
	CkaSign            = AttributeType(0x00000108)
	CkaSignRecover     = AttributeType(0x00000109)
	CkaVerify          = AttributeType(0x0000010A)
	CkaVerifyRecover   = AttributeType(0x0000010B)
	CkaDerive          = AttributeType(0x0000010C)
	CkaStartDate       = AttributeType(0x00000110)
	CkaEndDate         = AttributeType(0x00000111)
	CkaModus           = AttributeType(0x00000120)
	CkaModusBits       = AttributeType(0x00000121)
	CkaPublicExponent  = AttributeType(0x00000122)
	CkaPrivateExponent = AttributeType(0x00000123)
	CkaPrime1          = AttributeType(0x00000124)
	CkaPrime2          = AttributeType(0x00000125)
	CkaExponent1       = AttributeType(0x00000126)
	CkaExponent2       = AttributeType(0x00000127)
	CkaCoefficient     = AttributeType(0x00000128)
	CkaPublicKeyInfo   = AttributeType(0x00000129)
	CkaPrime           = AttributeType(0x00000130)
	CkaSubprime        = AttributeType(0x00000131)
	CkaBase            = AttributeType(0x00000132)

	CkaPrimeBits    = AttributeType(0x00000133)
	CkaSubprimeBits = AttributeType(0x00000134)
	/* (To retain backwards-compatibility) */
	CkaSubPrimeBits = CkaSubprimeBits

	CkaValueBits        = AttributeType(0x00000160)
	CkaValueLen         = AttributeType(0x00000161)
	CkaExtractable      = AttributeType(0x00000162)
	CkaLocal            = AttributeType(0x00000163)
	CkaNeverExtractable = AttributeType(0x00000164)
	CkaAlwaysSensitive  = AttributeType(0x00000165)
	CkaKeyGenMechanism  = AttributeType(0x00000166)

	CkaModifiable = AttributeType(0x00000170)
	CkaCopyable   = AttributeType(0x00000171)

	/* new for v2.40 */
	CkaDestroyable = AttributeType(0x00000172)

	/* CKA_ECDSA_PARAMS is deprecated in v2.11,
	 * CKA_EC_PARAMS is preferred. */
	CkaEcdsaParams = AttributeType(0x00000180)
	CkaEcParams    = AttributeType(0x00000180)

	CkaEcPoint = AttributeType(0x00000181)

	/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
	 * are new for v2.10. Deprecated in v2.11 and onwards. */
	CkaSecondaryAuth = AttributeType(0x00000200) /* Deprecated */
	CkaAuthPinFlags  = AttributeType(0x00000201) /* Deprecated */

	CkaAlwaysAuthenticate = AttributeType(0x00000202)

	CkaWrapWithTrusted = AttributeType(0x00000210)

	ckfArrayAttribute = AttributeType(0x40000000)

	CkaWrapTemplate   = AttributeType(ckfArrayAttribute | AttributeType(0x00000211))
	CkaUnwrapTemplate = AttributeType(ckfArrayAttribute | AttributeType(0x00000212))

	CkaOtpFormat               = AttributeType(0x00000220)
	CkaOtpLength               = AttributeType(0x00000221)
	CkaOtpTimeInterval         = AttributeType(0x00000222)
	CkaOtpUserFriendlyMode     = AttributeType(0x00000223)
	CkaOtpChallengeRequirement = AttributeType(0x00000224)
	CkaOtpTimeRequirement      = AttributeType(0x00000225)
	CkaOtpCounterRequirement   = AttributeType(0x00000226)
	CkaOtpPinRequirement       = AttributeType(0x00000227)
	CkaOtpCounter              = AttributeType(0x0000022E)
	CkaOtpTime                 = AttributeType(0x0000022F)
	CkaOtpUserIdentifier       = AttributeType(0x0000022A)
	CkaOtpServiceIdentifier    = AttributeType(0x0000022B)
	CkaOtpServiceLogo          = AttributeType(0x0000022C)
	CkaOtpServiceLogoType      = AttributeType(0x0000022D)

	CkaGostr3410Params = AttributeType(0x00000250)
	CkaGostr3411Params = AttributeType(0x00000251)
	CkaGost28147Params = AttributeType(0x00000252)

	CkaHwFeatureType = AttributeType(0x00000300)
	CkaResetOnInit   = AttributeType(0x00000301)
	CkaHasReset      = AttributeType(0x00000302)

	CkaPixelX                 = AttributeType(0x00000400)
	CkaPixelY                 = AttributeType(0x00000401)
	CkaResolution             = AttributeType(0x00000402)
	CkaCharRows               = AttributeType(0x00000403)
	CkaCharColumns            = AttributeType(0x00000404)
	CkaColor                  = AttributeType(0x00000405)
	CkaBitsPerPixel           = AttributeType(0x00000406)
	CkaCharSets               = AttributeType(0x00000480)
	CkaEncodingMethods        = AttributeType(0x00000481)
	CkaMimeTypes              = AttributeType(0x00000482)
	CkaMechanismType          = AttributeType(0x00000500)
	CkaRequiredCmsAttributes  = AttributeType(0x00000501)
	CkaDefatCmsAttributes     = AttributeType(0x00000502)
	CkaSupportedCmsAttributes = AttributeType(0x00000503)
	CkaAllowedMechanisms      = AttributeType(ckfArrayAttribute | AttributeType(0x00000600))
)

// An Attribute represents a PKCS#11 CK_ATTRIBUTE type.
type Attribute struct {
	Type  AttributeType
	Value []byte
}

// NewAttribute is a helper function that populates a new Attribute for common data types. This function will
// panic if value is not of type bool, int, uint, string, []byte or time.Time (or is nil).
func NewAttribute(attributeType AttributeType, value interface{}) *Attribute {
	// Use pkcs11 helper.
	pAttr := pkcs11.NewAttribute(uint(attributeType), value)
	return &Attribute{
		Type:  attributeType,
		Value: pAttr.Value,
	}
}

// NewAttributewithId is a helper function that populates a new slice of Attributes with the provided ID.
// This function returns an error if the ID is an empty slice.
func NewAttributewithId(id []byte) ([]*Attribute, error) {
	if err := notNilBytes(id, "id"); err != nil {
		return nil, err
	}
	return []*Attribute{NewAttribute(CkaId, id)}, nil
}

// NewAttributewithLabel is a helper function that populates a new slice of Attributes with the provided ID and Label.
// This function returns an error if either the ID or the Label is an empty slice.
func NewAttributewithLabel(id, label []byte) (a []*Attribute, err error) {
	if a, err = NewAttributewithId(id); err != nil {
		return nil, err
	}
	if err := notNilBytes(label, "label"); err != nil {
		return nil, err
	}
	a = append(a, NewAttribute(CkaLabel, label))
	return
}

// mergeAttributes combines a template with additional attributes. Where conflicts occur, the user supplied definition
// wins.
func mergeAttributes(template []*pkcs11.Attribute, additional []*Attribute) []*pkcs11.Attribute {
	attributes := make(map[uint]*pkcs11.Attribute)

	for _, a := range template {
		attributes[a.Type] = a
	}

	for _, a := range additional {
		attributes[uint(a.Type)] = &pkcs11.Attribute{Value: a.Value, Type: uint(a.Type)}
	}

	var result []*pkcs11.Attribute
	for _, v := range attributes {
		result = append(result, v)
	}
	return result
}

// wrapAttributes converts the internal PKCS11 attribute slice to a Crypto11 Attribute list
func wrapAttributes(template []*pkcs11.Attribute) []*Attribute {
	var result []*Attribute
	for _, v := range template {
		result = append(result, &Attribute{
			Type:  AttributeType(v.Type),
			Value: v.Value,
		})
	}

	return result
}

// validateAttributeHasID returns an error if the CkaId attribute is missing or empty
func attributeHasID(attributes []*Attribute, name string) error {
	found := false
	for _, attr := range attributes {
		if attr.Type == CkaId {
			if err := notNilBytes(attr.Value, fmt.Sprintf("%s id attribute", name)); err != nil {
				return err
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("missing %s id attribute", name)
	}
	return nil
}

// keyPairAttributeHasID ensures both sets of attributes has a CkaId attribute
func keyPairAttributesHaveID(public, private []*Attribute) error {
	if err := attributeHasID(public, "public"); err != nil {
		return err
	}
	if err := attributeHasID(private, "private"); err != nil {
		return err
	}
	return nil
}
