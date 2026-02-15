namespace WrestlingPlatform.Web.Services;

public sealed class WorkflowState
{
    public Guid? AthleteUserId { get; set; }
    public Guid? AthleteProfileId { get; set; }
    public Guid? CoachUserId { get; set; }
    public Guid? CoachProfileId { get; set; }
    public Guid? TeamId { get; set; }
    public Guid? EventId { get; set; }
    public Guid? DivisionId { get; set; }
    public Guid? MatchId { get; set; }
    public Guid? StreamId { get; set; }

    public void Clear()
    {
        AthleteUserId = null;
        AthleteProfileId = null;
        CoachUserId = null;
        CoachProfileId = null;
        TeamId = null;
        EventId = null;
        DivisionId = null;
        MatchId = null;
        StreamId = null;
    }
}
