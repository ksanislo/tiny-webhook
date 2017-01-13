# tiny-webhook.py
Tiny dependency free Python webhook target for GitHub

When a webhook call is received from github, this will fire off the corrosponding script under ./scripts/:repo_owner:/:repository:/:event:

For example, a new release in the TitleDB repo will trigger ./scripts/ksanislo/TitleDB/release where as a push to this repository will start a run of ./scripts/ksanislo/tiny-webhook/push

Returned status codes are 202 for a sucessfull hook launch, 501 on an unknown event type, and 500 for other fatal errors.
