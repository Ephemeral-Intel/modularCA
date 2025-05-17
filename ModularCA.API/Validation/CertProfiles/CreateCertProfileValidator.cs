using FluentValidation;
using ModularCA.Core.Models;
using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.API.Validation.CertProfiles
{
    public class CreateCertProfileValidator : AbstractValidator<CreateCertProfileRequest>
    {
        private static readonly string[] AllowedKeyUsages =
        {
        "digitalSignature", "keyEncipherment", "dataEncipherment", "keyAgreement",
        "keyCertSign", "crlSign", "encipherOnly", "decipherOnly"
    };

        private static readonly string[] AllowedExtendedKeyUsages =
        {
        "serverAuth", "clientAuth", "codeSigning", "emailProtection",
        "timeStamping", "OCSPSigning", "smartcardLogon"
    };

        public CreateCertProfileValidator()
        {
            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Name is required.")
                .MaximumLength(100);

            RuleFor(x => x.Description)
                .MaximumLength(255);

            RuleFor(x => x.IncludeRootInChain)
                .NotNull();

            RuleFor(x => x.KeyUsage)
                .NotEmpty()
                .Must(BeValidKeyUsages)
                .WithMessage($"KeyUsage must be a comma-separated list of: {string.Join(", ", AllowedKeyUsages)}");

            RuleFor(x => x.ExtendedKeyUsage)
                .Must(BeValidEKUs)
                .When(x => !string.IsNullOrEmpty(x.ExtendedKeyUsage))
                .WithMessage($"ExtendedKeyUsage must be a comma-separated list of: {string.Join(", ", AllowedExtendedKeyUsages)}");

            RuleFor(x => x.ValidityPeriod)
                .NotEmpty()
                .Matches(@"^P(\d+Y)?(\d+M)?(\d+D)?$")
                .WithMessage("ValidityPeriod must be an ISO 8601 duration like P1Y, P6M, or P90D.");
        }

        private bool BeValidKeyUsages(string input) =>
            input.Split(',', StringSplitOptions.RemoveEmptyEntries)
                 .Select(x => x.Trim())
                 .All(x => AllowedKeyUsages.Contains(x));

        private bool BeValidEKUs(string input) =>
            input.Split(',', StringSplitOptions.RemoveEmptyEntries)
                 .Select(x => x.Trim())
                 .All(x => AllowedExtendedKeyUsages.Contains(x));
    }

}