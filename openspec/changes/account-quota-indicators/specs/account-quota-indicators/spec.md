## ADDED Requirements
### Requirement: Upcoming quota reset
The dashboard SHALL show the earliest future known quota reset in upstream account rows and details, with the window label and browser-local timestamp including timezone. Missing or elapsed reset timestamps SHALL NOT be presented as upcoming.

#### Scenario: Several quota windows
- **WHEN** an account has multiple future reset timestamps
- **THEN** the earliest is displayed and all future windows are available in the tooltip

### Requirement: Reset credit badge
The dashboard SHALL show a coin badge for OpenAI and Anthropic accounts with the reported available reset-credit count, including zero. Unknown counts SHALL be displayed as unknown rather than zero. Displaying the badge SHALL NOT redeem credits.

#### Scenario: Credit count unavailable
- **WHEN** the account summary has no reset-credit count
- **THEN** the badge displays a question mark with an accessible explanation
