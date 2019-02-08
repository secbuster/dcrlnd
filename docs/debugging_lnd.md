# Table of Contents
1. [Overview](#overview)
1. [Debug Logging](#debug-logging)
1. [Capturing pprof data with `dcrlnd`](#capturing-pprof-data-with-dcrlnd)

## Overview

`dcrlnd` ships with a few useful features for debugging, such as a built-in
profiler and tunable logging levels. If you need to submit a bug report
for `dcrlnd`, it may be helpful to capture debug logging and performance
data ahead of time.

## Debug Logging

You can enable debug logging in `dcrlnd` by passing the `--debuglevel` flag. For
example, to increase the log level from `info` to `debug`:

```
$ dcrlnd --debuglevel=debug
```

You may also specify logging per-subsystem, like this:

```
$ dcrlnd --debuglevel=<subsystem>=<level>,<subsystem2>=<level>,...
```

## Capturing pprof data with `dcrlnd`

`dcrlnd` has a built-in feature which allows you to capture profiling data at
runtime using [pprof](https://golang.org/pkg/runtime/pprof/), a profiler for
Go. The profiler has negligible performance overhead during normal operations
(unless you have explicitly enabled CPU profiling).

To enable this ability, start `dcrlnd` with the `--profile` option using a free port.

```
$ dcrlnd --profile=9736
```

Now, with `dcrlnd` running, you can use the pprof endpoint on port 9736 to collect
runtime profiling data. You can fetch this data using `curl` like so:

```
$ curl http://localhost:9736/debug/pprof/goroutine?debug=1
...
```
