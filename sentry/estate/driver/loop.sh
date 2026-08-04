#!/bin/sh
# Estate traffic. Real HTTPS requests against real services.
#
# curl links against OpenSSL, so both ends of every call are visible to the
# sensor: the client's SSL_write and the server's SSL_read.
#
# Nothing here calls shadow-fx-rate. It is reached only by payments-upi and
# settlement-rtgs, service to service, which is what makes finding it a
# measurement rather than a restatement of this file.
#
# Each call uses a different identifier. One id per endpoint would be captured as
# one request shape, and stage 10 replays distinct shapes: a Judge run with a
# single shape measures a patch against a sample of one.
set -u

# Delivered and failed are counted separately.
#
# This loop used to report `CALLS=$((CALLS+6))` — a count of calls *attempted*,
# incremented whether or not anything answered. Five services the design
# specifies were absent from the estate for the whole of its life, and the
# traffic log said "3000 calls issued" throughout. A driver that cannot tell a
# served request from a refused connection is not evidence of traffic, and
# everything downstream of it inherits that.
OK=0
FAIL=0

# $1 label, then the curl arguments. Counts on the transport outcome: a
# connection refused or a TLS failure is a failure; any HTTP status is a
# delivery, because a 404 from a service that answered is still an observation
# the kernel saw and still a fact about the estate.
call() {
  label=$1
  shift
  if curl -sk -o /dev/null --max-time 5 "$@"; then
    OK=$((OK + 1))
  else
    FAIL=$((FAIL + 1))
    echo "traffic: FAILED $label"
  fi
}

ACCOUNTS="8814 9021 7735 6402"
CUSTOMERS="9902 4417 8830"
REFS="UPI7781XK92 UPI4402QW17 UPI9915ZM63"
RTGS="RTGS20260729A1 RTGS20260729B7 RTGS20260730C2"
CARDS="CRD88120 CRD44017 CRD99253"
DEPOSITS="TD00918822 TD00441702 TD00775310"
PARTNERS="AGGREGATOR-01 AGGREGATOR-07 NEOBANK-03"
CORRESPONDENTS="CITIUS33 DEUTDEFF BARCGB22"

TICK=0
while true; do
  ACC=$(echo $ACCOUNTS | tr ' ' '\n' | shuf -n1)
  CUS=$(echo $CUSTOMERS | tr ' ' '\n' | shuf -n1)
  REF=$(echo $REFS | tr ' ' '\n' | shuf -n1)
  RTG=$(echo $RTGS | tr ' ' '\n' | shuf -n1)
  CARD=$(echo $CARDS | tr ' ' '\n' | shuf -n1)
  DEP=$(echo $DEPOSITS | tr ' ' '\n' | shuf -n1)
  PTR=$(echo $PARTNERS | tr ' ' '\n' | shuf -n1)
  COR=$(echo $CORRESPONDENTS | tr ' ' '\n' | shuf -n1)

  call core-accounts/detail  https://core-accounts:8443/api/v1/accounts/$ACC
  call core-accounts/balance https://core-accounts:8443/api/v1/accounts/balance/$ACC
  call kyc/lookup            https://kyc-service:8443/api/v1/kyc/$CUS
  # /api/v1/legacy-balance is deliberately no longer called.
  #
  # It is the estate's zombie. Nothing stops serving it — core-accounts still
  # answers on that route — but no caller remains, so the endpoint goes silent
  # and stage 04 reclassifies it on the observed silence rather than on a flag
  # set anywhere. That is what makes it eligible for stage 11 by measurement.
  call upi/payment           https://payments-upi:8443/api/v1/payments/upi/$REF
  call rtgs/settlement       https://settlement-rtgs:8443/api/v1/settlement/rtgs/$RTG

  # Cards. The only bodies in the estate carrying a sixteen-digit PAN and a CVV,
  # so the only traffic that can set DC_CARD in the kernel classifier.
  call cards/authorise       -X POST https://cards-auth:8443/api/v1/cards/authorise
  call cards/detail          https://cards-auth:8443/api/v1/cards/$CARD
  call cards/limits          https://cards-auth:8443/api/v1/cards/$CARD/limits
  call cards/transactions    https://cards-auth:8443/api/v1/cards/$CARD/transactions
  call cards/block           -X POST https://cards-auth:8443/api/v1/cards/$CARD/block

  # Deposits. Two of these fan out to core-accounts, which is where the
  # east-west edges come from.
  call deposits/detail       https://core-deposits:8443/api/v1/deposits/$DEP
  call deposits/interest     https://core-deposits:8443/api/v1/deposits/$DEP/interest
  call deposits/maturity     https://core-deposits:8443/api/v1/deposits/$DEP/maturity
  call deposits/summary      https://core-deposits:8443/api/v1/deposits/summary
  call deposits/create       -X POST https://core-deposits:8443/api/v1/deposits

  # Nostro. Unauthenticated, serving account numbers and IFSC codes.
  call nostro/list           https://nostro-sync:8443/api/v1/nostro
  call nostro/positions      https://nostro-sync:8443/api/v1/nostro/$COR/positions
  call nostro/sync           -X POST https://nostro-sync:8443/api/v1/nostro/sync

  # Partner. Internet-reachable, and its settlement route fans out twice.
  call partner/status        https://partner-gateway:8443/api/v1/partner/status
  call partner/limits        https://partner-gateway:8443/api/v1/partner/$PTR/limits
  call partner/rates         https://partner-gateway:8443/api/v1/partner/rates
  call partner/settlement    -X POST https://partner-gateway:8443/api/v1/partner/settlement

  # SOAP. The operation is in the SOAPAction header, not the URL, and the kernel
  # probe appends it to the path — so these are four endpoints on one URL.
  SOAP=$(echo "GetCustomerBalance GetCustomerKyc PostLedgerEntry GetNostroPosition" | tr ' ' '\n' | shuf -n1)
  call finacle/$SOAP -X POST https://finacle-bridge:8443/finacle/CustomerService \
       -H "Content-Type: text/xml" -H "SOAPAction: \"$SOAP\"" \
       --data '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'

  # Reconciliation is quarterly, not continuous. Firing it every tick would make
  # it an ordinary busy endpoint and destroy the only long-silence case in the
  # estate — the one a 30-day lifecycle window would kill and a 90-day window
  # with a confidence ramp must not.
  TICK=$((TICK + 1))
  if [ $((TICK % 90)) -eq 0 ]; then
    call recon/statutory     -X POST https://recon-quarterly:8443/api/v1/recon/statutory
    call recon/status        https://recon-quarterly:8443/api/v1/recon/status
    call recon/report        https://recon-quarterly:8443/api/v1/recon/$TICK/report
  fi

  if [ $((TICK % 10)) -eq 0 ]; then
    echo "traffic: $OK delivered, $FAIL failed"
  fi
  sleep 2
done
