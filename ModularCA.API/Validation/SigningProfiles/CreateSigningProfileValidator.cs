using FluentValidation;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.API.Validation.SigningProfiles
{
    public class CreateSigningProfileValidator : AbstractValidator<CreateSigningProfileRequest>
    {
        private static readonly string[] AllowedAlgorithms = new[]
        {
        "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
        "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"
    };

        public CreateSigningProfileValidator()
        {
            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Name is required.")
                .MaximumLength(100);

            RuleFor(x => x.Description)
                .MaximumLength(255);

            RuleFor(x => x.SignatureAlgorithm)
                .Must(a => AllowedAlgorithms.Contains(a))
                .WithMessage($"SignatureAlgorithm must be one of: {string.Join(", ", AllowedAlgorithms)}");

            RuleFor(x => x.ValidityPeriodMin)
                .Must(BeWithinRange)
                .WithMessage("ValidityPeriod must be between 30 days and 5 years.");

            RuleFor(x => x.ValidityPeriodMax)
                .Must(BeWithinRange)
                .WithMessage("ValidityPeriod must be between 30 days and 5 years.");

            RuleFor(x => x.IsDefault)
                .NotNull();
        }
        private bool BeWithinRange(string iso)
        {
            try
            {
                var duration = System.Xml.XmlConvert.ToTimeSpan(iso);
                return duration >= TimeSpan.FromDays(30) && duration <= TimeSpan.FromDays(1825);
            }
            catch
            {
                return false;
            }
        }
    }
}