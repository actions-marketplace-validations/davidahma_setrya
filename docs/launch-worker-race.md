# The source row was gone. The assistant still knew the hostname.

In Setrya’s sample workspace, a customer’s onboarding notes were deleted. Then a handoff job that had already read those notes finished. Two teammates reopened the handoff and asked which hostname the customer had used. Both got `cobalt-bridge.example`.

That is the failure the Setrya demo reproduces. It pauses a real worker in the example application, applies deletion, lets the worker finish and asks again. The fixed worker checks the revisions it read before it publishes. Both teammates lose the hostname and can still retrieve the team's launch date, October 18.

Try both receipts on your laptop with fictional data:

```sh
python -m pip install setrya==1.2.0
setrya demo --output workspace
setrya replay workspace/broken
setrya replay workspace/guarded
```

The first replay exits 1. The second passes the application checks and leaves a provider follow-up open. You can send the evidence to someone who has never run the app and they can replay the same result.

For your own service, pick one private fact, one fact to keep and one authenticated route. Start with deletion alone. Add the worker checkpoint when you're ready to test whether a delayed write can undo it. [Get a verdict on a pull request](https://github.com/davidahma/setrya/blob/v1.2.0/docs/github-action.md)
