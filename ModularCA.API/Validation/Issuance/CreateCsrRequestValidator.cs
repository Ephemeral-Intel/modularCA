using FluentValidation;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Validation.Issuance
{
    public class CreateCsrRequestValidator : AbstractValidator<CreateCsrRequest>
    {
        public CreateCsrRequestValidator()
        {
            RuleFor(x => x.CertificateProfileId)
                .NotEmpty().WithMessage("CSR (PEM) must be provided.");

            RuleFor(x => x.SigningProfileId)
                .NotEmpty().WithMessage("Signing profile is required.");

            RuleFor(x => x.SubjectName)
                .NotEmpty().WithMessage("Subject name is required.");

            RuleFor(x => x.KeyAlgorithm)
                .Must(alg => alg == "RSA" || alg == "ECDSA")
                .WithMessage("Key algorithm must be either 'RSA' or 'ECDSA'.");

            RuleFor(x => x.KeySize)
                .Must((request, keySize) => ValidKeySize(keySize, request.KeyAlgorithm))
                .WithMessage(request => $"Key size {request.KeySize} is not valid for algorithm {request.KeyAlgorithm}.");

            RuleFor(x => x.SignatureAlgorithm)
                .Must((request, signatureAlgorithm) => ValidSignatureAlgorithm(request.KeyAlgorithm, signatureAlgorithm))
                .WithMessage(string.Format("Signature algorithm {0} is not valid for key algorithm {1}.", "{PropertyValue}", "{KeyAlgorithm}"));
        }

        public static bool ValidKeySize(string keySize, string keyAlgorithm)
        {
            if (keyAlgorithm == "RSA")
            {
                return keySize == "2048" || keySize == "4096";
            }
            else if (keyAlgorithm == "ECDSA")
            {
                return keySize == "P-256" || keySize == "P-384" || keySize == "P-521";
            }
            return false;
        }

        public static bool ValidSignatureAlgorithm(string keyAlgorithm, string signatureAlgorithm)
        {
            if (keyAlgorithm == "RSA")
            {
                return signatureAlgorithm == "SHA256withRSA" || signatureAlgorithm == "SHA384withRSA" || signatureAlgorithm == "SHA512withRSA";
            }
            else if (keyAlgorithm == "ECDSA")
            {
                return signatureAlgorithm == "SHA256withECDSA" || signatureAlgorithm == "SHA384withECDSA" || signatureAlgorithm == "SHA512withECDSA";
            }
            return false;
        }


    }
}