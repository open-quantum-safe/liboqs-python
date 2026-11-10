# Governance

> **THIS PROJECT HAS NO ACTIVE MAINTENANCE AND IS UNDER CARETAKER STATUS. CONTRIBUTORS WANTED.**
>
> This project currently has no active Committers or Maintainers. An Interim Caretaker keeps minimal workflow going, but users should not expect timely reviews, fixes or releases. This status is declared under the [OQS TSC Caretaker Process](https://github.com/open-quantum-safe/tsc/blob/main/governance/caretaker_procedure.md), which defines the Interim Caretaker's appointment, oversight and relief of duty.

## Basic principles

This project aims to operate by the following principles:

- **Openness**: The project will be open in its operation, open to contributions, and produce open source software.
- **Respect**: The project will foster respectful interactions with all participants.
- **Scientific integrity**: The project will follow advancements in cryptographic research and will be guided by standards and best practices with a slant towards favouring the advancement of long term research goals over short term commercial interests.
- **Best effort**: The project will do the best its members can do to provide support to its users without making over-ambitious promises; no user shall be led to assume this code is meant to be used in commercial offerings.

Decision making in the project will follow the principles above, and be governed first and foremost by reason and mutually respectful interaction between all participants.
The project will aim to build consensus for decisions, and will where possible operate by the approach of [lazy consensus](https://community.apache.org/committers/decisionMaking.html).
If decisions cannot be reached using lazy consensus, voting will be used to come to a resolution.

## Community and Roles

The OQS community is open to all who would like to participate in the project following its principles, including academic, industry, public sector, and individual contributors.

The following roles exist in the project:

### Users

A **User** is a person or organization using software produced by the project.

Responsibilities:

- Abide by the [license][LICENSE.txt]
- Consider participating in the project!

### Community Members

A **Community Member** is a User who interacts with the project, for example by participating in discussions on Github or mailing lists, or in project meetings.

Responsibilities:

- Follow the [code of conduct](CODE_OF_CONDUCT.md)

### Contributors

A **Contributor** is a Community Member who contributes directly to the project by submitting code or documentation, or actively participating in issues or pull requests on Github.

### Committers

A **Committer** is a Contributor with increased interest in the project who helps review pull requests and actively participates in discussions about the project. Committers will be members of the open-quantum-safe GitHub organization and will have "write" permissions in GitHub.

Responsibilities:

- Further the goals of the project.
- Monitor and respond to GitHub issues.
- Review and merge pull requests in cooperation with other Committers.
- Assist with security releases when required.
- Jointly agree on general and technical guidelines for the project.
- Jointly agree project priorities.
- Participate in discussions and project meetings.

### Release managers

A release manager is a Contributor versed in creating releases of the project.

Responsibilities:

- Manage the release cycle, incl. creation of suitable user documentation.
- Execution of downstream tests ascertaining quality of releases.

### Maintainers

A **Maintainer** is a Committer with additional responsibilities and experience. Maintainers will have "administrative" permissions in GitHub.

Responsibilities:

- Assess project status and role assignments.
- Propose communication about the project.
- Propose changes to this governance document.

### Interim Caretaker

An **Interim Caretaker** is appointed only while this project has no active Maintainer. The role exists to keep minimal workflow moving, and is explicitly not a Maintainer role — a Caretaker is not expected to have deep familiarity with the project's code base or underlying cryptography.

Responsibilities:

- Merge self-contained, low-risk pull requests that pass CI (typo fixes, dependency bumps, CI/build fixes, documentation updates).
- Leave open, or close with an explanation, any pull request that touches cryptographic logic, the public API, or project architecture.
- Route incoming security reports to the recorded upstream/algorithm contact or the OQS security-tracking process.
- Keep this file and the README accurate: the project remains labeled `INACTIVE/UNMAINTAINED` for the duration of the Caretaker period.
- May use AI assistance to help review or triage, but merge decisions remain a human judgement call, never autonomous AI action on the repository.

Caretakers are not expected to: develop new features, resolve non-security bugs, set direction or architecture, or commit to any response-time SLA.

Caretakers are nominated and appointed by the OQS TSC, and the role ends when a new Maintainer is voted in. See the TSC repository for the full nomination, appointment, and relief-of-duty process.

### Change of role

Any Community Member may become a Contributor by creating a pull request (PR) and getting it successfully reviewed and merged by Committers.

Any Contributor can become a Committer by contributing sufficient code and displaying deep subject matter knowledge in discussions such that a majority of Committers vote for this change of role. A Maintainer can veto such a vote. Such a veto can be overruled by a 2/3 majority of Committers.

As such a voting decision may be considered subjective, Contributors striving to become Committers are encouraged to ask for advice from Committers/Maintainers as to what they can do to obtain this role. Baseline requirements for contributions are documented in [CONTRIBUTING.md](CONTRIBUTING.md). Any Contributor can create a discussion item to request a vote to become Committer.

Any Committer can become a Maintainer by majority vote of voting Committers. A current Maintainer can veto such a vote. Such a veto can be overruled by a 2/3 majority of all Committers.

A Maintainer is not permitted to remove another Maintainer's GitHub privileges.

A Committer may be automatically moved to Contributor status if not actively contributing by discussion or PR review during the last 90 days or by voluntarily suspending this status (e.g., by taking a ["Leave of absence"](#leave-of-absence)). If a Maintainer loses or relinquishes the Committer status and, hence, the Maintainer status, the Committers have to determine whether a new Maintainer needs to be elected.

Any person violating the [code of conduct](CODE_OF_CONDUCT.md), consistently not fulfilling the role responsibilities, or for other reasons can lose the role held if a simple majority of Committers votes for such removal and no Maintainer vetos that decision. If a Maintainer is to be removed from that role a 2/3 majority of Committers must agree.

Depending on the reason for removal, a Maintainer may be converted to Emeritus status. Emeritus Maintainers may still be consulted on some project matters, and can be returned to Maintainer status if their availability changes and a simple majority of Committers agrees.

### Leave of absence

Any Committer may voluntarily step down from the role for a documented period of time, losing voting rights for that time period. The period is documented in this file next to the person's name below.  At the end of this time period, the Committer automatically regains their voting rights.

A leave of absence may not be longer than a year. If the Committer needs to be away for longer than that, they must step down from that role unconditionally, and regaining that role becomes subject of normal procedures to become Committer, as described in ["Change of role"](#change-of-role) above.

## Voting

Change of role or changes to this document is subject to voting.

Votes are to be executed by way of open GitHub discussions. No quorum is needed for votes open for 4 weeks. Urgent matters may be decided by majority vote among Maintainers or 2/3 majority by all Committers within an arbitrary voting period.

## Current Maintainers and Committers

## Interim Caretaker

@dstebila

### Maintainers

none

### Committers

none

### Release managers

none

## Afterword

*This governance document was based in part of the [Falco Project governance document](https://github.com/falcosecurity/evolution/blob/main/GOVERNANCE.md).
