using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Web.Services;

public sealed record StateOption(string Code, string Name);

public sealed record GradeOption(int Value, string Label);

public static class FormOptions
{
    public static IReadOnlyList<StateOption> UsStates { get; } =
    [
        new("AL", "Alabama"),
        new("AK", "Alaska"),
        new("AZ", "Arizona"),
        new("AR", "Arkansas"),
        new("CA", "California"),
        new("CO", "Colorado"),
        new("CT", "Connecticut"),
        new("DE", "Delaware"),
        new("DC", "District of Columbia"),
        new("FL", "Florida"),
        new("GA", "Georgia"),
        new("HI", "Hawaii"),
        new("ID", "Idaho"),
        new("IL", "Illinois"),
        new("IN", "Indiana"),
        new("IA", "Iowa"),
        new("KS", "Kansas"),
        new("KY", "Kentucky"),
        new("LA", "Louisiana"),
        new("ME", "Maine"),
        new("MD", "Maryland"),
        new("MA", "Massachusetts"),
        new("MI", "Michigan"),
        new("MN", "Minnesota"),
        new("MS", "Mississippi"),
        new("MO", "Missouri"),
        new("MT", "Montana"),
        new("NE", "Nebraska"),
        new("NV", "Nevada"),
        new("NH", "New Hampshire"),
        new("NJ", "New Jersey"),
        new("NM", "New Mexico"),
        new("NY", "New York"),
        new("NC", "North Carolina"),
        new("ND", "North Dakota"),
        new("OH", "Ohio"),
        new("OK", "Oklahoma"),
        new("OR", "Oregon"),
        new("PA", "Pennsylvania"),
        new("RI", "Rhode Island"),
        new("SC", "South Carolina"),
        new("SD", "South Dakota"),
        new("TN", "Tennessee"),
        new("TX", "Texas"),
        new("UT", "Utah"),
        new("VT", "Vermont"),
        new("VA", "Virginia"),
        new("WA", "Washington"),
        new("WV", "West Virginia"),
        new("WI", "Wisconsin"),
        new("WY", "Wyoming")
    ];

    public static IReadOnlyList<StateOption> UsStatesWithAny { get; } =
    [
        new(string.Empty, "All States"),
        .. UsStates
    ];

    public static IReadOnlyList<GradeOption> GradeOptions { get; } =
    [
        new(0, "K"),
        new(1, "1st Grade"),
        new(2, "2nd Grade"),
        new(3, "3rd Grade"),
        new(4, "4th Grade"),
        new(5, "5th Grade"),
        new(6, "6th Grade"),
        new(7, "7th Grade"),
        new(8, "8th Grade"),
        new(9, "9th Grade"),
        new(10, "10th Grade"),
        new(11, "11th Grade"),
        new(12, "12th Grade"),
        new(13, "College Freshman"),
        new(14, "College Sophomore"),
        new(15, "College Junior"),
        new(16, "College Senior")
    ];

    private static readonly IReadOnlyList<decimal> ElementaryWeights =
    [
        45m, 50m, 55m, 60m, 65m, 70m, 75m, 80m, 85m, 90m, 95m, 100m, 105m, 110m, 120m, 130m, 140m, 160m
    ];

    private static readonly IReadOnlyList<decimal> MiddleSchoolWeights =
    [
        70m, 75m, 80m, 85m, 90m, 95m, 100m, 105m, 110m, 115m, 120m, 125m, 130m, 135m, 140m, 145m, 152m, 160m, 172m, 189m, 215m, 285m
    ];

    private static readonly IReadOnlyList<decimal> HighSchoolWeights =
    [
        106m, 113m, 120m, 126m, 132m, 138m, 144m, 150m, 157m, 165m, 175m, 190m, 215m, 285m
    ];

    private static readonly IReadOnlyList<decimal> CollegeWeights =
    [
        125m, 133m, 141m, 149m, 157m, 165m, 174m, 184m, 197m, 285m
    ];

    public static IReadOnlyList<decimal> WeightClassesFor(CompetitionLevel level)
    {
        return level switch
        {
            CompetitionLevel.ElementaryK6 => ElementaryWeights,
            CompetitionLevel.MiddleSchool => MiddleSchoolWeights,
            CompetitionLevel.HighSchool => HighSchoolWeights,
            CompetitionLevel.College => CollegeWeights,
            _ => HighSchoolWeights
        };
    }
}
