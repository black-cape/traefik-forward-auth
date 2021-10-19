A fork of https://github.com/geek-cookbook/traefik-forward-auth with the following fix

* Add optional configuration to disable SSL cert verification for local development
* Add CORs headers around all responses
* Add GitLab CI to build the Docker image
* Adds support to verify users by using the bearer token stored in this authorization header
* Correct mapping of keycloak user to user data struct 
* Add wait-for-it wrapper script to make sure keycloak is up and running first 
