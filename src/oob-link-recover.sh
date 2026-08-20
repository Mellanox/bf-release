#!/bin/sh
set -eu

IF=oob_net0
CARRIER_FILE="/sys/class/net/${IF}/carrier"

is_bf4()
{
        # Check if the device is a BF4
        if [ "$(lspci -nD 2> /dev/null | grep -w "15b3:a2df" | awk '{print $1}' | head -1)" != "" ]; then
                return 0
        fi

        return 1
}

# The recovery is needed on the BlueField-4 OOB port only; leave
# BlueField-1/2/3 untouched.
if ! is_bf4; then
    echo "Not a BlueField-4 device, exiting"
    exit 0
fi

echo "Checking carrier state for ${IF}"

if [ ! -e "$CARRIER_FILE" ]; then
    echo "Carrier file ${CARRIER_FILE} does not exist, exiting"
    exit 0
fi

# The LAN743x TX DMA controller can stall while reading TX descriptors
# when scatter-gather is enabled, freezing all TX on the OOB interface
# while carrier stays up. Keep scatter-gather disabled on this interface;
# re-applying an already-off setting is a no-op.
echo "${IF}: disabling scatter-gather (LAN743x TX DMA stall workaround)"
ethtool -K "$IF" sg off || {
    echo "${IF}: failed to disable scatter-gather" >&2
    true
}

CARRIER="$(cat "$CARRIER_FILE" 2>/dev/null)" || {
    echo "${IF}: cannot read carrier state, exiting"
    exit 0
}
echo "${IF} carrier state: ${CARRIER}"

if [ "$CARRIER" = "0" ]; then
    echo "${IF}: carrier is down, cycling interface"

    ip link set dev "$IF" down || {
        echo "${IF}: failed to bring interface down" >&2
        true
    }

    sleep 1

    ip link set dev "$IF" up || {
        echo "${IF}: failed to bring interface up" >&2
        true
    }

    # Carrier takes a few seconds to return after link-up (autoneg);
    # poll briefly so the completion log reflects the real outcome.
    CARRIER=unknown
    for _ in 1 2 3 4 5; do
        sleep 1
        CARRIER="$(cat "$CARRIER_FILE" 2>/dev/null || echo unknown)"
        if [ "$CARRIER" = "1" ]; then
            break
        fi
    done
    echo "${IF}: recovery cycle completed, carrier now: ${CARRIER}"
else
    echo "${IF}: carrier is up, nothing to do"
fi
