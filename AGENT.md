Remonse is a project whose goals are described in README.md

There should be multiple modes of operation for the single output binary:
* A service with an API target that runs on machines, validating requests for actions and running them
* A service that can be run centrally, supporting certificate revocation through OCSP
* A web service that can either run locally or remotely:
    * Allowing you to view and sign requests for actions, scoped with time-bounds and audience targets (machine names)
    * Enable you to take a signed request and send it to a target machine (or machines) and stream the result of execution back (stdout/stderr)
    * The above options, but as CLI commands

It is extremely important to maintain the highest level of best security practices with this project.
For faster development, when running with a -dev flag the web service UI should source files locally from a directory to allow them to be updated rapidly.

For testing, a local Hashicorp Vault instance will be used for a PKCE OIDC flow as well as a standalone OPA service
