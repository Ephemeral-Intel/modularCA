using FluentValidation;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.API.Validation.Issuance
{
    public class SubmitCertificateRequestValidator : AbstractValidator<SubmitCertificateRequest>
    {
        public SubmitCertificateRequestValidator()
        {
            RuleFor(x => x.CsrPem)
                .NotEmpty().WithMessage("CSR (PEM) must be provided.")
                .Must(pem => pem.Contains("BEGIN CERTIFICATE REQUEST"))
                .WithMessage("CSR must be a valid PEM string.");

            RuleFor(x => x.SigningProfileId)
                .NotEmpty().WithMessage("Signing profile is required.");
        }
    }
}