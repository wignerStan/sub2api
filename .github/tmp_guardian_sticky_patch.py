from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "backend/internal/service/openai_guardian_route.go",
    "\treturn true\n}\n\nfunc (s *OpenAIGatewayService) getOpenAIAccountForSchedulingContext",
    "\treturn true\n}\n\nfunc isOpenAIAccountSchedulableForRequest(ctx context.Context, account *Account) bool {\n"
    "\tif IsOpenAICodexGuardianRequest(ctx) && account != nil && account.IsOpenAI() && account.IsOpenAIOAuthLike() {\n"
    "\t\treturn isOpenAICodexGuardianAccountSchedulable(account)\n"
    "\t}\n"
    "\treturn account != nil && account.IsSchedulable()\n"
    "}\n\nfunc (s *OpenAIGatewayService) getOpenAIAccountForSchedulingContext",
)

replace_once(
    "backend/internal/service/openai_account_scheduler.go",
    "if shouldClearOpenAIStickySessionForRequest(ctx, account, req.RequestedModel) || account.Platform != NormalizeOpenAICompatiblePlatform(req.Platform) || !account.IsOpenAICompatible() || !account.IsSchedulable() {",
    "if shouldClearOpenAIStickySessionForRequest(ctx, account, req.RequestedModel) || account.Platform != NormalizeOpenAICompatiblePlatform(req.Platform) || !account.IsOpenAICompatible() || !isOpenAIAccountSchedulableForRequest(ctx, account) {",
)

test = '''func TestOpenAICodexGuardianSchedulingPredicateIgnoresNormalQuotaOnly(t *testing.T) {
\tquotaReset := time.Now().Add(time.Hour)
\taccount := &Account{
\t\tPlatform:         PlatformOpenAI,
\t\tType:             AccountTypeOAuth,
\t\tStatus:           StatusActive,
\t\tSchedulable:      true,
\t\tRateLimitResetAt: &quotaReset,
\t}
\tguardianCtx := context.WithValue(context.Background(), openAICodexGuardianRouteContextKey{}, OpenAICodexGuardianRouteReview)

\trequire.True(t, isOpenAIAccountSchedulableForRequest(guardianCtx, account))
\trequire.False(t, isOpenAIAccountSchedulableForRequest(context.Background(), account))

\toverload := time.Now().Add(time.Minute)
\taccount.OverloadUntil = &overload
\trequire.False(t, isOpenAIAccountSchedulableForRequest(guardianCtx, account))
}

'''
replace_once(
    "backend/internal/service/openai_guardian_route_test.go",
    "func TestOpenAICodexGuardianRuntimeBlockIgnoresOnly429(t *testing.T) {",
    test + "func TestOpenAICodexGuardianRuntimeBlockIgnoresOnly429(t *testing.T) {",
)
