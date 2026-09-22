#!/bin/bash
#
# Recover kubelet static pods that lost the boot-time race against DOCA
# hugepage provisioning (RM-5266141).
#
# Hugepages for apps such as SNAP are applied late in boot by mlnx_bf_configure
# (triggered by the ib_umad modprobe install hook), while kubelet can start and
# evaluate static pod admission before that happens. Because this kubelet runs
# in standalone mode (no API server), its hugepages-* node capacity is captured
# once at process startup and never re-polled, so a pod rejected this way stays
# rejected — re-presenting its manifest does not help — until kubelet itself is
# restarted. This script detects that specific failure and restarts kubelet once
# instead of requiring a manual "systemctl restart kubelet".
#
# Scope: only static pods that actually request a hugepages-* resource (SNAP is
# optional, so this is a no-op on boxes that don't use it), and only admission
# failures from this boot.

set -u

KUBELET_D=/etc/kubelet.d
MAX_ATTEMPTS=20
SLEEP_SECS=15
VERIFY_ATTEMPTS=3
VERIFY_SLEEP_SECS=5
TAG=kubelet-hugepages-recovery

log()
{
	logger -t "$TAG" "$@"
}

find_hugepage_manifests()
{
	# Every static pod manifest that requests a hugepages-* resource. The grep
	# requires the string to appear as an actual resource key (indented,
	# followed by ":"), so a stray mention in a label, annotation or comment
	# does not pull an unrelated pod in.
	grep -lE '^[[:space:]]+hugepages-[0-9A-Za-z]+:' "$KUBELET_D"/*.yaml 2>/dev/null
}

pod_identity()
{
	# "<namespace>/<name>" of one manifest, or nothing if it cannot be read.
	#
	# metadata.name and metadata.namespace are anchored to the two-space
	# indentation directly under "metadata:", so neither "generateName:" nor a
	# label such as "app.kubernetes.io/name:" can be picked up by mistake, and
	# the scan stops at the next top-level key so nothing outside the metadata
	# block is considered. A manifest indented some other way therefore yields
	# nothing, which the caller reports rather than skipping silently.
	awk '
		/^metadata:/ { in_meta = 1; next }
		in_meta && /^[^[:space:]]/ { exit }
		in_meta && /^  name:[[:space:]]/ { name = $2 }
		in_meta && /^  namespace:[[:space:]]/ { namespace = $2 }
		END {
			if (name == "")
				exit
			if (namespace == "")
				namespace = "default"
			print namespace "/" name
		}
	' "$1"
}

pod_running()
{
	# Filtering is left to crictl so that it applies to the sandbox's own
	# namespace and name fields: grepping the rendered listing would match a
	# line anywhere, so an unrelated pod whose namespace or runtime string
	# happens to contain this name would be reported as running. --name is a
	# substring match, which is what we want here - kubelet suffixes the
	# manifest name with "-<nodename>" to form the actual pod identity.
	#
	# Restricted to Ready sandboxes: a stale or NotReady sandbox record -
	# plausible right after a reboot, before CRI-O has garbage-collected it -
	# must not count as running. -q limits output to sandbox IDs, so any
	# output at all means such a sandbox exists.
	local ns=${1%%/*}
	local name=${1#*/}

	timeout 5 crictl pods --namespace "$ns" --name "$name" --state ready -q 2>/dev/null | grep -q .
}

pod_admission_failed()
{
	# Matched against kubelet's klog field layout as of v1.34.1 (captured from
	# a real DPU); re-verify this pattern when bumping the kubelet version.
	#
	# All three greps must hit the same line: the pod identity, the rejection
	# itself, and a hugepages-specific reason - otherwise a pod failing
	# admission for an unrelated reason (real CPU/memory shortage, say) would
	# be "recovered" by a pointless kubelet restart.
	timeout 5 journalctl -u kubelet -b --no-pager 2>/dev/null \
		| grep -F "pod=\"$1" \
		| grep -F 'UnexpectedAdmissionError' \
		| grep -q 'hugepages-'
}

pod_running_after_restart()
{
	# CRI-O is usually busier right after a kubelet restart, so one query
	# hitting the 5s timeout is not yet evidence that the pod failed to come
	# up. Retry a few times before reporting it, purely so the log is not
	# misleading - the restart has already happened either way.
	local pod=$1
	local attempt

	for ((attempt = 1; attempt <= VERIFY_ATTEMPTS; attempt++)); do
		if pod_running "$pod"; then
			return 0
		fi
		if [ "$attempt" -lt "$VERIFY_ATTEMPTS" ]; then
			sleep "$VERIFY_SLEEP_SECS"
		fi
	done

	return 1
}

any_pod_stuck()
{
	local pod

	for pod in "$@"; do
		if ! pod_running "$pod" && pod_admission_failed "$pod"; then
			return 0
		fi
	done

	return 1
}

mapfile -t manifests < <(find_hugepage_manifests)
if [ "${#manifests[@]}" -eq 0 ]; then
	# No hugepage-dependent static pod configured on this box.
	exit 0
fi

pods=()
for manifest in "${manifests[@]}"; do
	pod=$(pod_identity "$manifest")
	if [ -n "$pod" ]; then
		pods+=("$pod")
	else
		log "ignoring ${manifest}: requests hugepages but its metadata.name could not be read"
	fi
done

if [ "${#pods[@]}" -eq 0 ]; then
	exit 0
fi

# Wait out the boot-time window: hugepage provisioning and the first admission
# attempt may still be racing. Only a failure that is still present after the
# full grace window (MAX_ATTEMPTS x SLEEP_SECS = 5 minutes) is the stale
# capacity one, so restart kubelet only then.
for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
	if ! any_pod_stuck "${pods[@]}"; then
		exit 0
	fi
	sleep "$SLEEP_SECS"
done

log "restarting kubelet: stale hugepages admission failure detected for: ${pods[*]}"
systemctl restart kubelet

sleep "$SLEEP_SECS"
for pod in "${pods[@]}"; do
	if ! pod_running_after_restart "$pod"; then
		log "kubelet restarted but ${pod} is still not running - needs manual investigation"
	fi
done
