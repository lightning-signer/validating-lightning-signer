# Contributing
# Contributing to VLS

First off, thanks for taking the time to contribute to VLS! :pray:

The following is a set of guidelines for contributing to VLS and its packages, which are hosted in the [Validating Lightning Signer group](https://gitlab.com/lightning-signer) on GitLab. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a merge request.

#### Table Of Contents

[Code of Conduct](#code-of-conduct)

[I don't want to read this whole thing, I just have a question!!!](#i-dont-want-to-read-this-whole-thing-i-just-have-a-question)

[What should I know before I get started?](#what-should-i-know-before-i-get-started)

* [VLS and Packages](#VLS-and-packages)
* [VLS Design Decisions](#design-decisions)

[How Can I Contribute?](#how-can-i-contribute)

* [Reporting Bugs](#reporting-bugs)
* [Suggesting Enhancements](#suggesting-enhancements)
* [Your First Code Contribution](#your-first-code-contribution)
* [Merge Requests](#Merge-requests)

[Styleguides](#styleguides)

* [Git Commit Messages](#git-commit-messages)
* [Documentation Styleguide](#documentation-styleguide)

[Additional Notes](#additional-notes)

* [Issue and Merge Request Labels](#issue-and-merge-request-labels)

## Code of Conduct

This project and everyone participating in it is governed by the [VLS Code of Conduct](https://gitlab.com/lightning-signer/validating-lightning-signer/-/wikis/VLS-Code-of-Conduct). By participating, you are expected to uphold this code. Please report unacceptable behavior to the Code of Conduct Team.

## I don't want to read this whole thing I just have a question!!!

> **Note:** Please don't file an issue to ask a question. You'll get faster results by using the resources below.

We have an official message board where the community chimes in with helpful advice if you have questions:

* [VLS General Matrix Chat](https://matrix.to/#/#vls-general:matrix.org)
* [VLS Dev Chat](https://matrix.to/#/#vls-dev:matrix.org)

# What should I know before I get started?

### VLS and Packages

VLS is made up of a handful of repos:

* [validating-lightning-signer](https://gitlab.com/lightning-signer/validating-lightning-signer) - Validating Lightning Signer (VLS) core. A library and reference implementation for a signer module to secure Lightning nodes.
* [txoo](https://gitlab.com/lightning-signer/txoo) - A UTXO oracle for Bitcoin
* [serde-bolt](https://gitlab.com/lightning-signer/serde-bolt) - Lightning BOLT style serialization/deserialization
* [CLN+VLS - System Test](https://gitlab.com/lightning-signer/vls-hsmd) - System test for a C-Lightning hsmd replacement that connects to VLS
* [lnrod](https://gitlab.com/lightning-signer/lnrod) - A Lightning node implementation in Rust based on the LDK and the Validating Lightning Signer projects. Aims to be production ready at some point.
* [VLS Container](https://gitlab.com/lightning-signer/vls-container) - Containers for the VLS project, including Docker.

### Design Decisions

When we make a significant decision in how we maintain the project and what we can or cannot support, we will document it in the [design Wiki](https://gitlab.com/lightning-signer/docs/-/wikis/Design). If you have a question around how we do things, check to see if it is documented there. If it is _not_ documented there, please ask your question in our [VLS Dev Matrix Chat](https://matrix.to/#/#vls-dev:matrix.org).

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for VLS. Following these guidelines helps maintainers and the community understand your report :pencil:, reproduce the behavior :computer: :computer:, and find related reports :mag_right:.

Before creating bug reports, please check [this list](#before-submitting-a-bug-report) as you might find out that you don't need to create one. When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report). Fill out [the required template](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/.gitlab/issue_templates/Default.md?ref_type=heads), the information it asks for helps us resolve issues faster.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

#### Before Submitting A Bug Report

* Determine [**which repository the problem should be reported in**](#VLS-and-packages).
* Perform a [**cursory search**](https://gitlab.com/groups/lightning-signer/-/issues) to see if the problem has already been reported. If it has **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitLab issues](https://docs.gitlab.com/ee/user/project/issues/). After you've determined [which repository](#VLS-and-packages) your bug is related to, create an issue on that repository and provide the following information by filling in [the template](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/.gitlab/issue_templates/Default.md?ref_type=heads).

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. For example, start by explaining how you started VLS, e.g. which command exactly you used in the terminal, or how you started VLS otherwise. When listing steps, **don't just say what you did, but explain how you did it**.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitLab projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Optionally, include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.
* **If you're reporting that VLS crashed**, include a crash report with a stack trace from the operating system. Include the crash report in the issue in a [code block](https://help.github.com/articles/markdown-basics/#multiple-lines), a file attachment, or put it in a [snippet](https://gitlab.com/dashboard/snippets) and provide link to that snippet.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened and share more information using the guidelines below.

Provide more context by answering these questions:

* **Did the problem start happening recently** (e.g. after updating to a new version of VLS) or was this always a problem?
* If the problem started happening recently, **can you reproduce the problem in an older version of VLS?** What's the most recent version in which the problem doesn't happen? You can download older versions of VLS from [the releases page](https://gitlab.com/lightning-signer/validating-lightning-signer/-/releases).
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which conditions it normally happens.

Include details about your configuration and environment:

* **Which version of VLS are you using?** You can get the exact version by running `git describe --tags --long --always --match='v*.*'` in a `vls` tree, or by running `make list-versions` in a `vls-hsmd` tree.
* **What's the name and version of the OS you're using**?
* **Are you running VLS in a virtual machine?** If so, which VM software are you using and which operating systems and versions are used for the host and the guest?
* **Which **[**packages**](#VLS-and-packages)** do you have installed?**

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for VLS, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion :pencil: and find related suggestions :mag_right:.

Before creating enhancement suggestions, please check [this list](#before-submitting-an-enhancement-suggestion) as you might find out that you don't need to create one. When you are creating an enhancement suggestion, please [include as many details as possible](#how-do-i-submit-a-good-enhancement-suggestion). Fill in [the template](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/.gitlab/issue_templates/Feature%20Request.md?ref_type=heads), including the steps that you imagine you would take if the feature you're requesting existed.

#### Before Submitting An Enhancement Suggestion

* Check if you're using [the latest version of VLS](https://gitlab.com/lightning-signer/validating-lightning-signer/-/releases).
* **Determine **[**which repository the enhancement should be suggested in**](#VLS-and-packages)**.**
* Perform a [**cursory search**](https://gitlab.com/groups/lightning-signer/-/issues) to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Enhancement Suggestion?

Enhancement suggestions are tracked as [GitLab issues](https://docs.gitlab.com/ee/user/project/issues/). After you've determined [which repository](#VLS-and-packages) your enhancement suggestion is related to, create an issue on that repository and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as much detail as possible.
* **Provide specific examples to demonstrate the steps**. Include copy/pasteable snippets which you use in those examples, as [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Optionally, include screenshots and animated GIFs** which help you demonstrate the steps or point out the part of VLS which the suggestion is related to.
* **Explain why this enhancement would be useful** to most VLS users and isn't something that can or should be implemented as a by individual users.
* **Specify which version of VLS you're using.** You can get the exact version by running `git describe --tags --long --always --match='v*.*'` in a `vls` tree, or by running `make list-versions` in a `vls-hsmd` tree.
* **Specify the name and version of the OS you're using.**

### Your First Code Contribution

Unsure where to begin contributing to VLS? You can start by looking through these `Starter Issues` and `Help-Wanted` issues:

* [Starter Issues](https://gitlab.com/groups/lightning-signer/-/issues/?sort=created_date&state=opened&label_name%5B%5D=StarterIssue&first_page_size=20) - issues which should only require a few lines of code, and a test or two.
* [Help wanted issues](https://gitlab.com/groups/lightning-signer/-/issues/?sort=popularity&state=opened&label_name%5B%5D=Help-Wanted&first_page_size=20) - issues which should be a bit more involved than `Starter` issues.

Both issue lists are sorted by popularity. While not perfect, popularity is a reasonable proxy for impact a given change will have.

### Merge Requests

The process described here has several goals:

- Maintain VLS quality and safety
- Fix problems that are important to users
- Engage the community in working toward the best possible VLS
- Enable a sustainable system for VLS' maintainers to review contributions

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference the relevant folder or module as a prefix for commit messages (e.g. `core: xxxx` or `protocol: xxxx`)
* Reference issues and merge requests liberally after the first line
* When only changing documentation, include `[ci skip]` in the commit title

## Additional Notes

### Issue and Merge Request Labels

This section lists the labels we use to help us track and manage issues and merge requests. Most labels are used across all VLS repositories, but some are specific to `lightning-signer/validating-lightning-signer`.

[GitLab search](https://docs.gitlab.com/ee/user/search/) makes it easy to use labels for finding groups of issues or merge requests you're interested in.

For example, you might be interested in:

* [Starter Issues](https://gitlab.com/groups/lightning-signer/-/issues?label_name%5B%5D=StarterIssue)
* [Help Wanted](https://gitlab.com/groups/lightning-signer/-/issues?label_name%5B%5D=Help-Wanted)
* [Triage Issues](https://gitlab.com/groups/lightning-signer/-/issues?label_name%5B%5D=Triage)
* [High Priority Issues](https://gitlab.com/groups/lightning-signer/-/issues?label_name%5B%5D=Priority%3A%3AHigh)
* [Stuck Issues](https://gitlab.com/groups/lightning-signer/-/issues?label_name%5B%5D=Stuck)

Please open an issue on `VLS` if you have suggestions for new labels, and if you notice some labels are missing on some repositories, then please open an issue on that repository.