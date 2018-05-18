/*
Package lntest provides testing utilities for the dcrlnd repository.

This package contains infrastructure for integration tests that launch full
dcrlnd nodes in a controlled environment and interact with them via RPC. Using a
NetworkHarness, a test can launch multiple dcrlnd nodes, open channels between
them, create defined network topologies, and anything else that is possible with
RPC commands.
*/
package lntest
