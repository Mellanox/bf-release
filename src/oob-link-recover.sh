#!/bin/sh
set -eu

CARRIER_TIMEOUT=10 # Seconds allowed for each carrier wait.

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

wait_for_carrier()
{
    # Check immediately, then poll for up to the requested number of seconds.
    # A zero timeout performs one check without sleeping.
    wait_remaining=${1:-$CARRIER_TIMEOUT}

    while :; do
        CARRIER="$(cat "$CARRIER_FILE" 2>/dev/null)" || {
            echo "${IF}: cannot read carrier state" >&2
            exit 1
        }

        case "$CARRIER" in
            1) return 0 ;;
            0) ;;
            *)
                echo "${IF}: unexpected carrier state: ${CARRIER}" >&2
                exit 1
                ;;
        esac

        [ "$wait_remaining" -gt 0 ] || return 1
        sleep 1
        wait_remaining=$((wait_remaining - 1))
    done
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

# Allow normal startup/link negotiation to complete before recovery.
if wait_for_carrier "$CARRIER_TIMEOUT"; then
    echo "${IF}: carrier is up; no recovery needed"
    exit 0
fi

# Timeout leaves CARRIER=0.
echo "${IF} carrier state: ${CARRIER}"

if [ "$CARRIER" = "0" ]; then
    echo "${IF}: restarting autonegotiation"

    # Handle unsupported or failed renegotiation without triggering set -e.
    if ethtool -r "$IF"; then
        if wait_for_carrier "$CARRIER_TIMEOUT"; then
            echo "${IF}: carrier restored after autonegotiation"
            exit 0
        fi
        echo "${IF}: autonegotiation did not restore carrier; cycling interface"
    else
        echo "${IF}: cannot restart autonegotiation; cycling interface"
    fi

    # Carrier may have returned while deciding to use the fallback.
    if wait_for_carrier 0; then
        echo "${IF}: carrier is now up; skipping interface cycle"
        exit 0
    fi

    ip link set dev "$IF" down || {
        echo "${IF}: failed to bring interface down; still attempting to bring it up" >&2
        true
    }

    sleep 1

    ip link set dev "$IF" up || {
        echo "${IF}: failed to bring interface up" >&2
        exit 1
    }

    if wait_for_carrier "$CARRIER_TIMEOUT"; then
        echo "${IF}: carrier restored after interface cycle"
    else
        echo "${IF}: recovery unsuccessful, carrier: ${CARRIER}" >&2
        exit 1
    fi
else
    echo "${IF}: carrier is up, nothing to do"
fi
